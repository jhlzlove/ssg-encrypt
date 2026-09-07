use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use kuchiki::{traits::TendrilSink, NodeRef};
use pbkdf2::pbkdf2_hmac;
use rand::{rng, Rng};
use serde::Deserialize;
use sha2::Sha256;
use walkdir::WalkDir;

const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Parser, Debug)]
#[command(name = "site-encrypt", version, about = "Encrypt marked static HTML content")]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(short, long, default_value = "public")]
    input: PathBuf,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct Config {
    scanner: ScannerConfig,
    #[serde(default)]
    encryption: EncryptionConfig,
    #[serde(default)]
    output: OutputConfig,
    #[serde(default)]
    feeds: FeedsConfig,
    passwords: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ScannerConfig {
    #[serde(default = "default_extensions")]
    extensions: Vec<String>,
    /// Relative paths (forward slashes) to skip. Supports `*`, `?`, `**`.
    /// e.g. ["404.html", "print/**"]
    #[serde(default)]
    exclude: Vec<String>,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    /// CSS selector of the node carrying the password id (and receiving the
    /// payload attributes + injected unlock UI in self-contained mode).
    selector: String,
    /// Attribute on the matched node holding the password id (alias into
    /// `[passwords]`).
    password_id_attribute: String,
    #[serde(default)]
    hint_attribute: Option<String>,
    /// Optional: CSS selector of the node whose children should be encrypted
    /// instead of the matched node's own children. The payload attributes are
    /// still written onto the matched node and NO unlock markup is injected —
    /// use this when the page already provides its own unlock UI (e.g. a lock
    /// panel in one place and the content container elsewhere).
    #[serde(default)]
    content_selector: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EncryptionConfig {
    #[serde(default = "default_iterations")]
    iterations: u32,
}

impl Default for EncryptionConfig {
    fn default() -> Self { Self { iterations: default_iterations() } }
}

#[derive(Debug, Deserialize)]
struct OutputConfig {
    #[serde(default = "default_true")]
    remove_source_attributes: bool,
    #[serde(default = "default_class_name")]
    class_name: String,
    /// Copy for the injected unlock UI (self-contained mode only).
    #[serde(default)]
    ui: UiStrings,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            remove_source_attributes: true,
            class_name: default_class_name(),
            ui: UiStrings::default(),
        }
    }
}

/// Display strings for the injected unlock form (self-contained mode).
/// Ship your own language here; the companion `site-decrypt.js` only fills
/// the (initially empty) error element at runtime.
#[derive(Debug, Deserialize)]
struct UiStrings {
    #[serde(default = "default_password_label")]
    password_label: String,
    #[serde(default = "default_submit_label")]
    submit_label: String,
    #[serde(default = "default_noscript_text")]
    noscript_text: String,
}

impl Default for UiStrings {
    fn default() -> Self {
        Self {
            password_label: default_password_label(),
            submit_label: default_submit_label(),
            noscript_text: default_noscript_text(),
        }
    }
}

/// Feed redaction: entries linking to encrypted pages get their
/// `<content>`/`<summary>` (Atom) or `<description>` (RSS) replaced with a
/// placeholder. Titles stay public (same policy as list pages).
/// Matching is path-based (see `is_encrypted_url`): scheme/host are ignored,
/// so localhost preview builds and production builds redact identically.
#[derive(Debug, Deserialize)]
struct FeedsConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_feed_paths")]
    paths: Vec<String>,
    /// Subpath the site lives under, e.g. "/docs" for `example.com/docs`.
    /// Stripped from entry paths before mapping to local files.
    /// Empty (root-deployed sites, the common case) is fine.
    #[serde(default)]
    strip_prefix: String,
    /// Deprecated: use `strip_prefix`. Kept parsing so old configs don't
    /// break; only its path part was ever honoured anyway.
    #[serde(default)]
    base_url: String,
    #[serde(default = "default_feed_placeholder")]
    placeholder: String,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: default_feed_paths(),
            strip_prefix: String::new(),
            base_url: String::new(),
            placeholder: default_feed_placeholder(),
        }
    }
}

impl FeedsConfig {
    /// Effective path prefix to strip, honouring the deprecated alias.
    fn effective_prefix(&self) -> String {
        let direct = self.strip_prefix.trim_matches('/').to_string();
        if !direct.is_empty() {
            return direct;
        }
        url_path(&self.base_url).trim_matches('/').to_string()
    }
}

fn default_extensions() -> Vec<String> { vec!["html".into()] }
fn default_iterations() -> u32 { 600_000 }
fn default_true() -> bool { true }
fn default_class_name() -> String { "site-encrypt".into() }
fn default_password_label() -> String { "Password".into() }
fn default_submit_label() -> String { "Unlock".into() }
fn default_noscript_text() -> String {
    "JavaScript is required to decrypt this content.".into()
}
fn default_feed_paths() -> Vec<String> {
    vec![
        "**/atom.xml".into(),
        "**/rss.xml".into(),
        "**/feed.xml".into(),
        "**/index.xml".into(),
    ]
}
fn default_feed_placeholder() -> String {
    "This post is encrypted; open the original page to unlock it.".into()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw = fs::read_to_string(&cli.config).context("read config")?;
    let config: Config = toml::from_str(&raw).context("parse config TOML")?;
    validate_config(&config)?;
    validate_selectors(&config)?;

    let (files, encrypted, encrypted_files, html_errors) =
        process_html_tree(&cli.input, &config, cli.dry_run)?;
    for e in &html_errors {
        eprintln!("error: {e}");
    }

    // Never redact feeds from an incomplete encrypted-set: a failed page
    // would otherwise leak through its feed entry.
    let feeds_redacted = if html_errors.is_empty() {
        process_feeds(&cli.input, &config.feeds, &encrypted_files, cli.dry_run)?
    } else {
        eprintln!(
            "warning: skipping feed redaction due to {} HTML error(s)",
            html_errors.len()
        );
        0
    };

    println!(
        "Processed {files} HTML files; encrypted {encrypted} node(s); redacted {feeds_redacted} feed entrie(s).{}",
        if cli.dry_run { " (dry run)" } else { "" }
    );
    if !html_errors.is_empty() {
        bail!(
            "{} HTML file(s) failed; output may be partially processed — fix the errors, rebuild from clean, and re-run",
            html_errors.len()
        );
    }
    Ok(())
}

/// HTML pass with per-file error collection: one bad page (unknown password
/// id, missing attribute, …) is reported with its path while the rest of the
/// site keeps processing. A non-empty error list is fatal for the caller
/// (non-zero exit, no deploy) — see `main`.
fn process_html_tree(
    input: &Path,
    config: &Config,
    dry_run: bool,
) -> Result<(usize, usize, HashSet<String>, Vec<String>)> {
    let mut files = 0usize;
    let mut encrypted = 0usize;
    let mut encrypted_files: HashSet<String> = HashSet::new();
    let mut errors: Vec<String> = Vec::new();
    for entry in WalkDir::new(input).follow_links(false) {
        let entry = entry.context("walk input directory")?;
        if !entry.file_type().is_file() || !is_supported_html(entry.path(), &config.scanner.extensions) {
            continue;
        }
        let rel = rel_path(input, entry.path());
        if is_excluded(&rel, &config.scanner.exclude) {
            continue;
        }
        files += 1;
        match process_file(entry.path(), config, dry_run) {
            Ok(n) => {
                if n > 0 {
                    encrypted_files.insert(rel);
                }
                encrypted += n;
            }
            Err(e) => errors.push(format!("{rel}: {e:#}")),
        }
    }
    Ok((files, encrypted, encrypted_files, errors))
}

/// Fail fast on invalid CSS selectors (config bugs) so they don't get
/// reported once per file by the per-node error collection below.
fn validate_selectors(config: &Config) -> Result<()> {
    let probe: NodeRef = kuchiki::parse_html().one("<html><head></head><body></body></html>");
    for rule in &config.scanner.rules {
        probe
            .select(&rule.selector)
            .map_err(|_| anyhow::anyhow!("invalid CSS selector: {}", rule.selector))?;
        if let Some(cs) = rule.content_selector.as_deref() {
            probe
                .select(cs)
                .map_err(|_| anyhow::anyhow!("invalid content selector: {}", cs))?;
        }
    }
    Ok(())
}

fn validate_config(config: &Config) -> Result<()> {
    if config.scanner.rules.is_empty() { bail!("scanner.rules must contain at least one rule"); }
    if config.encryption.iterations < 100_000 { bail!("PBKDF2 iterations must be at least 100000"); }
    if config.output.class_name.trim().is_empty() { bail!("output.class_name cannot be empty"); }
    for rule in &config.scanner.rules {
        if rule.selector.trim().is_empty() { bail!("rule selector cannot be empty"); }
        if rule.password_id_attribute.trim().is_empty() {
            bail!("rule password_id_attribute cannot be empty");
        }
    }
    if config.feeds.enabled {
        if config.feeds.paths.is_empty() { bail!("feeds.paths cannot be empty when feeds.enabled"); }
        if config.feeds.placeholder.trim().is_empty() { bail!("feeds.placeholder cannot be empty when feeds.enabled"); }
    }
    Ok(())
}

/// Input-relative path with forward slashes, for matching + reporting.
fn rel_path(input: &Path, path: &Path) -> String {
    path.strip_prefix(input)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
}

fn is_excluded(rel: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| glob_match(p, rel))
}

/// Minimal glob over `/`-separated paths: `*` (within a segment),
/// `?` (one char, not `/`), `**` (any chars, across segments).
fn glob_match(pattern: &str, path: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => {
                if p.get(1) == Some(&b'*') {
                    // '**': zero or more chars, `/` included. A following `/`
                    // may also match zero segments (`**/x` matches `x`).
                    let mut rest = &p[2..];
                    while rest.first() == Some(&b'*') {
                        rest = &rest[1..];
                    }
                    for i in 0..=s.len() {
                        if go(rest, &s[i..]) {
                            return true;
                        }
                        if rest.first() == Some(&b'/') && go(&rest[1..], &s[i..]) {
                            return true;
                        }
                    }
                    false
                } else {
                    // '*': zero or more chars except `/`.
                    let rest = &p[1..];
                    let mut i = 0;
                    loop {
                        if go(rest, &s[i..]) {
                            return true;
                        }
                        if i >= s.len() || s[i] == b'/' {
                            return false;
                        }
                        i += 1;
                    }
                }
            }
            Some(b'?') => {
                if s.is_empty() || s[0] == b'/' {
                    return false;
                }
                go(&p[1..], &s[1..])
            }
            Some(c) => {
                if s.is_empty() || s[0] != *c {
                    return false;
                }
                go(&p[1..], &s[1..])
            }
        }
    }
    go(pattern.as_bytes(), path.as_bytes())
}

fn is_supported_html(path: &Path, extensions: &[String]) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|ext| extensions.iter().any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(ext)))
}

// ── Feed redaction ──────────────────────────────────────────────
// No XML dependency on purpose: feeds are machine-generated with escaped
// bodies, so targeted `<entry>`/`<item>` surgery is safe. Titles are kept
// public (same policy as list pages); only bodies are replaced.

fn process_feeds(
    input: &Path,
    cfg: &FeedsConfig,
    encrypted_files: &HashSet<String>,
    dry_run: bool,
) -> Result<usize> {
    if !cfg.enabled || encrypted_files.is_empty() {
        return Ok(0);
    }
    if !cfg.base_url.trim().is_empty() {
        eprintln!(
            "warning: [feeds].base_url is deprecated and its host part is ignored; \
             move the subpath (if any) to [feeds].strip_prefix"
        );
    }
    let prefix = cfg.effective_prefix();
    let mut redacted = 0usize;
    for entry in WalkDir::new(input).follow_links(false) {
        let entry = entry.context("walk input directory for feeds")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = rel_path(input, entry.path());
        if !cfg.paths.iter().any(|p| glob_match(p, &rel)) {
            continue;
        }
        redacted += redact_feed_file(entry.path(), &prefix, &cfg.placeholder, encrypted_files, dry_run)?;
    }
    Ok(redacted)
}

fn redact_feed_file(
    path: &Path,
    strip_prefix: &str,
    placeholder: &str,
    encrypted_files: &HashSet<String>,
    dry_run: bool,
) -> Result<usize> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let escaped = xml_escape(placeholder);
    // (start, end, replacement), applied back-to-front.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut count = 0usize;

    for kind in ["entry", "item"] {
        for (bs, be, _, _) in find_tag_blocks(&text, kind) {
            let block = &text[bs..be];
            let url = if kind == "entry" {
                find_atom_alternate(block)
            } else {
                find_tag_blocks(block, "link")
                    .first()
                    .map(|(_, _, a, b)| block[*a..*b].trim().to_string())
            };
            let Some(url) = url else { continue };
            if url.trim().is_empty() || !is_encrypted_url(strip_prefix, &url, encrypted_files) {
                continue;
            }
            for sub in ["content", "summary", "description"] {
                for (_, _, a, b) in find_tag_blocks(block, sub) {
                    edits.push((bs + a, bs + b, escaped.clone()));
                }
            }
            count += 1;
        }
    }

    // Already-desensitised reruns produce identical output; skip the write.
    if !dry_run && !edits.is_empty() {
        edits.sort_by(|a, b| b.0.cmp(&a.0));
        let mut out = text.clone();
        for (s, e, rep) in edits {
            out.replace_range(s..e, &rep);
        }
        if out != text {
            fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
        } else {
            count = 0;
        }
    }
    Ok(count)
}

/// `<link rel="alternate" href="...">` inside an Atom entry (any attr order).
fn find_atom_alternate(block: &str) -> Option<String> {
    let bytes = block.as_bytes();
    let mut i = 0;
    while let Some(rel) = block[i..].find("<link") {
        let s = i + rel;
        let after = s + "<link".len();
        if after < bytes.len()
            && (bytes[after].is_ascii_alphanumeric()
                || matches!(bytes[after], b'-' | b'_' | b':'))
        {
            i = after;
            continue;
        }
        let Some(tag_end) = open_tag_end(block, after) else {
            break;
        };
        let tag = &block[s..tag_end];
        if get_attr(tag, "rel").as_deref() == Some("alternate") {
            if let Some(href) = get_attr(tag, "href") {
                if !href.trim().is_empty() {
                    return Some(href);
                }
            }
        }
        i = tag_end;
    }
    None
}

/// Byte index just past the `>` closing an opening tag starting at `from`
/// (which points right after `<name`). Respects quotes; `None` if unterminated.
fn open_tag_end(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut j = from;
    let mut quote = 0u8;
    while j < bytes.len() {
        let c = bytes[j];
        if quote != 0 {
            if c == quote {
                quote = 0;
            }
        } else if c == b'"' || c == b'\'' {
            quote = c;
        } else if c == b'>' {
            return Some(j + 1);
        }
        j += 1;
    }
    None
}

/// Find non-overlapping `<tag ...>...</tag>` blocks.
/// Returns `(block_start, block_end, inner_start, inner_end)` byte offsets.
/// Self-closing tags are skipped; bodies are assumed not to nest same tags
/// (true for feeds, whose HTML bodies are escaped).
fn find_tag_blocks(text: &str, tag: &str) -> Vec<(usize, usize, usize, usize)> {
    let mut out = Vec::new();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(rel) = text[i..].find(&open) else {
            break;
        };
        let s = i + rel;
        let after = s + open.len();
        if after < bytes.len()
            && (bytes[after].is_ascii_alphanumeric()
                || matches!(bytes[after], b'-' | b'_' | b':'))
        {
            i = after;
            continue;
        }
        let Some(tag_end) = open_tag_end(text, after) else {
            break;
        };
        // Skip self-closing `<tag ... />`.
        let mut k = tag_end - 1;
        while k > s && matches!(bytes[k - 1], b' ' | b'\t' | b'\n' | b'\r') {
            k -= 1;
        }
        if bytes[k - 1] == b'/' {
            i = tag_end;
            continue;
        }
        let Some(rel2) = text[tag_end..].find(&close) else {
            break;
        };
        let inner_end = tag_end + rel2;
        out.push((s, inner_end + close.len(), tag_end, inner_end));
        i = inner_end + close.len();
    }
    out
}

/// Attribute value inside an open-tag string; handles `"`, `'` and unquoted.
fn get_attr(tag: &str, name: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while let Some(rel) = tag[i..].find(name) {
        let s = i + rel;
        let prev_ok = s == 0 || matches!(bytes[s - 1], b' ' | b'\t' | b'\n' | b'\r');
        let mut j = s + name.len();
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
            j += 1;
        }
        if prev_ok && bytes.get(j) == Some(&b'=') {
            j += 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            let q = *bytes.get(j)?;
            if q == b'"' || q == b'\'' {
                let start = j + 1;
                let end = tag[start..].find(q as char)? + start;
                return Some(tag[start..end].to_string());
            }
            let start = j;
            let mut end = j;
            while end < bytes.len()
                && !matches!(bytes[end], b' ' | b'\t' | b'\n' | b'\r' | b'>')
            {
                end += 1;
            }
            return Some(tag[start..end].to_string());
        }
        i = s + name.len();
    }
    None
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Map a feed entry URL back to files the HTML pass encrypted.
/// Matches by URL **path only** (`{rel}/index.html`, `{rel}.html`, `{rel}`),
/// ignoring scheme/host so localhost preview builds and production builds
/// behave identically. `strip_prefix` (no slashes needed) is removed first
/// for subpath deployments (`example.com/site`).
/// Consequence: planet/aggregator feeds mixing foreign entries must exclude
/// those feed files via `scanner.exclude` (same-path collisions would match).
fn is_encrypted_url(strip_prefix: &str, url: &str, encrypted_files: &HashSet<String>) -> bool {
    let mut rel = url_path(url).trim_matches('/').to_string();
    let base = strip_prefix.trim_matches('/');
    if !base.is_empty() {
        if rel == base {
            rel.clear();
        } else if let Some(rest) = rel.strip_prefix(&format!("{base}/")) {
            rel = rest.to_string();
        } else {
            return false;
        }
    }
    if rel.is_empty() {
        return encrypted_files.contains("index.html");
    }
    [format!("{rel}/index.html"), format!("{rel}.html"), rel.to_string()]
        .iter()
        .any(|c| encrypted_files.contains(c.as_str()))
}

/// Path component of a feed URL: drops `scheme://host` (or protocol-relative
/// `//host`), query string and fragment. Bare paths pass through unchanged.
fn url_path(url: &str) -> &str {
    let u = strip_url_suffix(url.trim());
    let has_authority = u.contains("://") || u.starts_with("//");
    if !has_authority {
        return u;
    }
    let s = match u.find("://") {
        Some(i) => &u[i + 3..],
        None => u.strip_prefix("//").unwrap_or(u),
    };
    if s.starts_with('/') {
        return s;
    }
    match s.find('/') {
        Some(i) => &s[i..],
        None => "",
    }
}

fn strip_url_suffix(u: &str) -> &str {
    let mut end = u.len();
    for (i, c) in u.char_indices() {
        if c == '#' || c == '?' {
            end = i;
            break;
        }
    }
    &u[..end]
}

fn process_file(path: &Path, config: &Config, dry_run: bool) -> Result<usize> {
    let html = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let document = kuchiki::parse_html().one(html);
    let mut targets: Vec<(NodeRef, usize)> = Vec::new();

    for (rule_index, rule) in config.scanner.rules.iter().enumerate() {
        let selected = document
            .select(&rule.selector)
            .map_err(|_| anyhow::anyhow!("invalid CSS selector: {}", rule.selector))?;
        for node in selected {
            targets.push((node.as_node().clone(), rule_index));
        }
    }

    let mut unique: Vec<(NodeRef, usize)> = Vec::new();
    for (node, rule_index) in targets {
        if !unique.iter().any(|(existing, _)| existing == &node) {
            unique.push((node, rule_index));
        }
    }

    let mut encrypted = 0usize;
    let mut node_errors: Vec<String> = Vec::new();
    for (node, rule_index) in &unique {
        let rule = &config.scanner.rules[*rule_index];
        match encrypt_node(node, rule, config, &document) {
            Ok(true) => encrypted += 1,
            Ok(false) => {}
            Err(e) => node_errors.push(format!("rule '{}': {e:#}", rule.selector)),
        }
    }
    if !node_errors.is_empty() {
        bail!("{}", node_errors.join("; "));
    }

    if !dry_run && encrypted > 0 {
        let mut out = Vec::new();
        document.serialize(&mut out).context("serialize HTML")?;
        fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    }

    Ok(encrypted)
}

fn encrypt_node(node: &NodeRef, rule: &Rule, config: &Config, document: &NodeRef) -> Result<bool> {
    let element = node.as_element().context("selected node is not an element")?;

    // Idempotency: a node that already carries a payload must not be
    // encrypted again (re-running on processed output would otherwise
    // encrypt the previous ciphertext / unlock markup a second time).
    if element
        .attributes
        .borrow()
        .get("data-site-encrypt-ciphertext")
        .is_some()
    {
        return Ok(false);
    }

    let password_id = element
        .attributes
        .borrow()
        .get(rule.password_id_attribute.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing password attribute '{}'",
                rule.password_id_attribute
            )
        })?
        .to_string();
    let password = config
        .passwords
        .get(&password_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no password configured for password id '{password_id}'; add it to [passwords] in the config"
            )
        })?
        .clone();

    // Split-UI mode: encrypt another node's children (e.g. the article
    // content container) while the payload attributes land on the matched
    // node (e.g. the lock panel). The page keeps its own unlock UI, so no
    // generic markup is injected.
    if let Some(content_selector) = rule.content_selector.as_deref() {
        let mut matches = document.select(content_selector).map_err(|_| {
            anyhow::anyhow!("invalid content selector: {}", content_selector)
        })?;
        let content = matches
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("content selector matched nothing: {}", content_selector)
            })?
            .as_node()
            .clone();
        if matches.next().is_some() {
            bail!(
                "content selector matched more than one node (expected exactly one): {}",
                content_selector
            );
        }

        let plaintext = content
            .children()
            .map(|child| serialize_node(&child))
            .collect::<Result<String>>()?;

        let encrypted = encrypt(&plaintext, &password, config.encryption.iterations)?;

        // Empty the content container (its `hidden` attribute, if any, stays).
        for child in content.children().collect::<Vec<_>>() {
            child.detach();
        }

        // Publish the payload on the matched (UI) node. `data-site-encrypt`
        // and `data-site-encrypt-target` are the discovery contract for the
        // companion `site-decrypt.js` (fixed names across SSGs).
        {
            let mut attrs = element.attributes.borrow_mut();
            attrs.insert("data-site-encrypt", "1".to_string());
            attrs.insert(
                "data-site-encrypt-version",
                FORMAT_VERSION.to_string(),
            );
            attrs.insert("data-site-encrypt-kdf", "pbkdf2-sha256".to_string());
            attrs.insert(
                "data-site-encrypt-iterations",
                encrypted.iterations.to_string(),
            );
            attrs.insert("data-site-encrypt-salt", encrypted.salt);
            attrs.insert("data-site-encrypt-nonce", encrypted.nonce);
            attrs.insert("data-site-encrypt-ciphertext", encrypted.ciphertext);
            attrs.insert(
                "data-site-encrypt-target",
                content_selector.to_string(),
            );
        }

        if config.output.remove_source_attributes {
            let mut attrs = element.attributes.borrow_mut();
            attrs.remove(rule.password_id_attribute.as_str());
            if let Some(h) = &rule.hint_attribute {
                attrs.remove(h.as_str());
            }
        }

        return Ok(true);
    }

    let hint = rule
        .hint_attribute
        .as_ref()
        .and_then(|a| {
            element
                .attributes
                .borrow()
                .get(a.as_str())
                .map(ToOwned::to_owned)
        });

    let plaintext = node
        .children()
        .map(|child| serialize_node(&child))
        .collect::<Result<String>>()?;

    let encrypted = encrypt(&plaintext, &password, config.encryption.iterations)?;
    let ui = build_unlock_markup(
        &encrypted,
        hint.as_deref(),
        &config.output.class_name,
        &config.output.ui,
    );

    let children: Vec<NodeRef> = node.children().collect();
    for child in children { child.detach(); }

    let fragment = kuchiki::parse_html().one(ui);
    let body = fragment.select_first("body").ok().map(|n| n.as_node().clone());
    let source = body.unwrap_or(fragment);
    for child in source.children().collect::<Vec<_>>() { node.append(child); }

    if config.output.remove_source_attributes {
        let mut attrs = element.attributes.borrow_mut();
        attrs.remove(rule.password_id_attribute.as_str());
        if let Some(h) = &rule.hint_attribute { attrs.remove(h.as_str()); }
    }

    Ok(true)
}

fn serialize_node(node: &NodeRef) -> Result<String> {
    let mut buf = Vec::new();
    node.serialize(&mut buf).context("serialize selected content")?;
    String::from_utf8(buf).context("HTML was not UTF-8")
}

fn encrypt(plaintext: &str, password: &str, iterations: u32) -> Result<Encrypted> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng().fill(&mut salt);
    rng().fill(&mut nonce);

    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).context("create AES-256-GCM key")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    Ok(Encrypted {
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        iterations,
    })
}

struct Encrypted {
    salt: String,
    nonce: String,
    ciphertext: String,
    iterations: u32,
}

fn build_unlock_markup(data: &Encrypted, hint: Option<&str>, class_name: &str, ui: &UiStrings) -> String {
    let hint_html = hint
        .map(|h| format!("<p class=\"{class_name}__hint\">{}</p>", html_escape(h)))
        .unwrap_or_default();
    format!(
        r#"<div class="{class_name}" data-site-encrypt="1" data-site-encrypt-version="{FORMAT_VERSION}" data-site-encrypt-kdf="pbkdf2-sha256" data-site-encrypt-iterations="{}" data-site-encrypt-salt="{}" data-site-encrypt-nonce="{}" data-site-encrypt-ciphertext="{}">{hint_html}<form class="{class_name}__form"><label><span class="{class_name}__label">{}</span><input class="{class_name}__password" type="password" autocomplete="current-password" required></label><button type="submit">{}</button><span class="{class_name}__error" role="alert" hidden></span></form><noscript>{}</noscript></div>"#,
        data.iterations,
        data.salt,
        data.nonce,
        data.ciphertext,
        html_escape(&ui.password_label),
        html_escape(&ui.submit_label),
        html_escape(&ui.noscript_text),
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_is_randomized() {
        let a = encrypt("hello", "password", 100_000).unwrap();
        let b = encrypt("hello", "password", 100_000).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn escaping_is_safe() {
        assert_eq!(html_escape("<x a=\"b\">&"), "&lt;x a=&quot;b&quot;&gt;&amp;");
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("**/atom.xml", "atom.xml"));
        assert!(glob_match("**/atom.xml", "tags/foo/atom.xml"));
        assert!(!glob_match("**/atom.xml", "atom.xml.bak"));
        assert!(glob_match("*.html", "index.html"));
        assert!(!glob_match("*.html", "blog/index.html"));
        assert!(glob_match("blog/**", "blog/a/b"));
        assert!(glob_match("?.html", "a.html"));
        assert!(!glob_match("?.html", "ab.html"));
        assert!(!glob_match("404.html", "en/404.html"));
        assert!(glob_match("**/404.html", "en/404.html"));
    }

    #[test]
    fn encrypted_url_mapping() {
        let set: HashSet<String> = HashSet::from(["blog/secret/index.html".to_string()]);
        // subpath deployment: prefix "/site" stripped, host ignored
        assert!(is_encrypted_url("/site", "https://example.com/site/blog/secret/", &set));
        assert!(is_encrypted_url("site", "https://example.com/site/blog/secret", &set));
        assert!(is_encrypted_url(
            "/site",
            "https://example.com/site/blog/secret/?x=1#frag",
            &set
        ));
        assert!(!is_encrypted_url("/site", "https://example.com/site/blog/open/", &set));
        assert!(!is_encrypted_url("/site", "https://example.com/other/blog/secret/", &set));
        assert!(!is_encrypted_url("/site", "https://example.com/site-blog/secret/", &set));
        // root deployment / localhost preview: empty prefix, host ignored
        assert!(is_encrypted_url("", "http://localhost:3000/blog/secret/", &set));
        assert!(is_encrypted_url("", "/blog/secret/", &set)); // bare path
        // same path on a foreign host still matches: planet/aggregator feeds
        // mixing outside entries must exclude those feed files instead.
        assert!(is_encrypted_url("/site", "https://other.example/site/blog/secret/", &set));
    }

    #[test]
    fn deprecated_base_url_still_feeds_prefix() {
        // old configs keep working: only the path part is honoured
        let cfg = FeedsConfig {
            enabled: true,
            paths: default_feed_paths(),
            strip_prefix: String::new(),
            base_url: "https://example.com/site".into(),
            placeholder: default_feed_placeholder(),
        };
        assert_eq!(cfg.effective_prefix(), "site");
        let cfg2 = FeedsConfig {
            strip_prefix: "/docs".into(),
            ..FeedsConfig::default()
        };
        assert_eq!(cfg2.effective_prefix(), "docs");
        assert_eq!(FeedsConfig::default().effective_prefix(), "");
    }

    fn test_feed_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("site-encrypt-test-{}-{}.xml", std::process::id(), name))
    }

    #[test]
    fn atom_feed_redaction() {
        let path = test_feed_path("atom");
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>t1</title><link rel="alternate" type="text/html" href="http://localhost:3000/blog/secret/"/><id>1</id><content type="html">&lt;p&gt;hidden body&lt;/p&gt;</content><summary>hidden summary</summary></entry>
<entry><title>t2</title><link href="https://example.com/blog/open/" rel="alternate"/><id>2</id><content type="html">&lt;p&gt;public body&lt;/p&gt;</content></entry>
</feed>"#;
        fs::write(&path, xml).unwrap();
        let files: HashSet<String> = HashSet::from(["blog/secret/index.html".to_string()]);
        let n = redact_feed_file(&path, "", "LOCKED", &files, false).unwrap();
        assert_eq!(n, 1);
        let out = fs::read_to_string(&path).unwrap();
        assert!(!out.contains("hidden body"));
        assert!(!out.contains("hidden summary"));
        assert!(out.contains("LOCKED"));
        assert!(out.contains("public body"));
        // rerun is a no-op
        let n2 = redact_feed_file(&path, "", "LOCKED", &files, false).unwrap();
        assert_eq!(n2, 0);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn rss_feed_redaction() {
        let path = test_feed_path("rss");
        let xml = r#"<?xml version="1.0"?>
<rss version="2.0"><channel>
<item><title>t1</title><link>https://example.com/blog/secret/</link><description><p>hidden rss</p></description></item>
<item><title>t2</title><link>https://example.com/blog/open/</link><description><p>public rss</p></description></item>
</channel></rss>"#;
        fs::write(&path, xml).unwrap();
        let files: HashSet<String> = HashSet::from(["blog/secret/index.html".to_string()]);
        let n = redact_feed_file(&path, "", "LOCKED", &files, false).unwrap();
        assert_eq!(n, 1);
        let out = fs::read_to_string(&path).unwrap();
        assert!(!out.contains("hidden rss"));
        assert!(out.contains("public rss"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn content_selector_mode_encrypts_elsewhere_and_skips_rerun() {
        let html = "<!DOCTYPE html><html><body>\
            <div class=\"encrypted\" id=\"encryptedBox\" data-password-key=\"k1\">\
            <form><input type=\"password\"></form></div>\
            <div class=\"article__content\" id=\"articleContent\" hidden><p>secret</p></div>\
            </body></html>";
        let document: NodeRef = kuchiki::parse_html().one(html);
        let rule = Rule {
            selector: "#encryptedBox".into(),
            password_id_attribute: "data-password-key".into(),
            hint_attribute: None,
            content_selector: Some("#articleContent".into()),
        };
        let config = Config {
            scanner: ScannerConfig {
                extensions: vec!["html".into()],
                exclude: vec![],
                rules: vec![],
            },
            encryption: EncryptionConfig { iterations: 100_000 },
            output: OutputConfig {
                remove_source_attributes: true,
                class_name: "site-encrypt".into(),
                ui: UiStrings::default(),
            },
            feeds: FeedsConfig::default(),
            passwords: HashMap::from([("k1".to_string(), "pw".to_string())]),
        };
        let node = document
            .select_first("#encryptedBox")
            .unwrap()
            .as_node()
            .clone();
        assert!(encrypt_node(&node, &rule, &config, &document).unwrap());
        // content container emptied, theme lock UI untouched
        let content = document
            .select_first("#articleContent")
            .unwrap()
            .as_node()
            .clone();
        assert_eq!(content.children().count(), 0);
        assert!(document.select_first("#encryptedBox form").is_ok());
        // payload published on the matched node, alias attr removed
        {
            let attrs = node.as_element().unwrap().attributes.borrow();
            assert_eq!(attrs.get("data-site-encrypt-version"), Some("1"));
            assert_eq!(attrs.get("data-site-encrypt-iterations"), Some("100000"));
            assert!(attrs.get("data-site-encrypt-salt").is_some());
            assert!(attrs.get("data-site-encrypt-nonce").is_some());
            assert!(attrs.get("data-site-encrypt-ciphertext").is_some());
            assert_eq!(
                attrs.get("data-site-encrypt-target"),
                Some("#articleContent")
            );
            assert!(attrs.get("data-password-key").is_none());
        }
        // re-running on processed output is a no-op (no double encryption)
        assert!(!encrypt_node(&node, &rule, &config, &document).unwrap());
    }

    fn test_rule(content_selector: Option<&str>) -> Rule {
        Rule {
            selector: "#box".into(),
            password_id_attribute: "data-password-key".into(),
            hint_attribute: None,
            content_selector: content_selector.map(str::to_string),
        }
    }

    fn test_config(passwords: &[(&str, &str)]) -> Config {
        Config {
            scanner: ScannerConfig {
                extensions: vec!["html".into()],
                exclude: vec![],
                rules: vec![],
            },
            encryption: EncryptionConfig { iterations: 100_000 },
            output: OutputConfig {
                remove_source_attributes: true,
                class_name: "site-encrypt".into(),
                ui: UiStrings::default(),
            },
            feeds: FeedsConfig::default(),
            passwords: passwords
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn parse_doc(html: &str) -> NodeRef {
        kuchiki::parse_html().one(html)
    }

    #[test]
    fn example_config_parses_and_validates() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("encrypt.example.toml");
        let raw = fs::read_to_string(&path).unwrap();
        let config: Config = toml::from_str(&raw).unwrap();
        validate_config(&config).unwrap();
        validate_selectors(&config).unwrap();
        assert!(!config.scanner.rules.is_empty());
    }

    #[test]
    fn content_selector_multiple_matches_is_an_error() {
        let document = parse_doc(
            "<!DOCTYPE html><html><body>\
            <div id=\"box\" data-password-key=\"k1\"></div>\
            <div class=\"c\"><p>a</p></div><div class=\"c\"><p>b</p></div>\
            </body></html>",
        );
        let rule = test_rule(Some(".c"));
        let config = test_config(&[("k1", "pw")]);
        let node = document.select_first("#box").unwrap().as_node().clone();
        let err = encrypt_node(&node, &rule, &config, &document).unwrap_err();
        assert!(
            err.to_string().contains("more than one"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn unknown_password_id_error_names_the_fix() {
        let document = parse_doc(
            "<!DOCTYPE html><html><body>\
            <div id=\"box\" data-password-key=\"nope\"></div>\
            <div id=\"content\"><p>secret</p></div>\
            </body></html>",
        );
        let rule = test_rule(Some("#content"));
        let config = test_config(&[("k1", "pw")]);
        let node = document.select_first("#box").unwrap().as_node().clone();
        let err = encrypt_node(&node, &rule, &config, &document).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nope"), "unexpected error: {msg}");
        assert!(msg.contains("[passwords]"), "unexpected error: {msg}");
    }

    #[test]
    fn html_tree_collects_per_file_errors_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("good.html"),
            "<!DOCTYPE html><html><body>\
            <div id=\"box\" data-password-key=\"k1\"></div>\
            <div id=\"content\"><p>secret</p></div>\
            </body></html>",
        )
        .unwrap();
        fs::write(
            dir.path().join("bad.html"),
            "<!DOCTYPE html><html><body>\
            <div id=\"box\" data-password-key=\"nope\"></div>\
            <div id=\"content\"><p>secret</p></div>\
            </body></html>",
        )
        .unwrap();
        let mut config = test_config(&[("k1", "pw")]);
        config.scanner.rules.push(Rule {
            selector: "#box".into(),
            ..test_rule(Some("#content"))
        });
        let (files, encrypted, encrypted_files, errors) =
            process_html_tree(dir.path(), &config, true).unwrap();
        assert_eq!(files, 2);
        assert_eq!(encrypted, 1);
        assert_eq!(encrypted_files.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("bad.html") && errors[0].contains("nope"),
            "unexpected errors: {errors:?}"
        );
    }
}
