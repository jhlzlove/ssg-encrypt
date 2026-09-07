use super::*;
use kuchiki::traits::TendrilSink;

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
    // exact path, any host, bare or absolute — all match
    assert!(is_encrypted_url("https://example.com/blog/secret/", &set));
    assert!(is_encrypted_url("https://example.com/blog/secret", &set));
    assert!(is_encrypted_url(
        "https://example.com/blog/secret/?x=1#frag",
        &set
    ));
    assert!(is_encrypted_url("http://localhost:3000/blog/secret/", &set));
    assert!(is_encrypted_url("/blog/secret/", &set)); // bare path
    // subpath deployments need no configuration: leading segments peel off
    assert!(is_encrypted_url("https://example.com/site/blog/secret/", &set));
    assert!(is_encrypted_url("https://example.com/docs/v2/blog/secret/", &set));
    // unrelated tails never match
    assert!(!is_encrypted_url("https://example.com/blog/open/", &set));
    assert!(!is_encrypted_url("https://example.com/site-blog/open/", &set));
    // fail-closed: a same-tail public page redacts too (placeholder
    // instead of body — never a leak)
    assert!(is_encrypted_url("https://other.example/archive/blog/secret/", &set));
}

#[test]
fn encrypted_url_homepage() {
    let set: HashSet<String> = HashSet::from(["index.html".to_string()]);
    assert!(is_encrypted_url("https://example.com/", &set));
    assert!(!is_encrypted_url("https://example.com/blog/", &set));
}

#[test]
fn feeds_reject_unknown_fields() {
    // `base_url` / `strip_prefix` were removed: old configs fail loudly
    // instead of silently ignoring the keys.
    let raw = r#"
enabled = true
base_url = "https://example.com/site"
"#;
    assert!(toml::from_str::<FeedsConfig>(raw).is_err());
    let raw2 = r#"
enabled = true
strip_prefix = "/docs"
"#;
    assert!(toml::from_str::<FeedsConfig>(raw2).is_err());
}

#[test]
fn rule_password_id_attribute_defaults() {
    let raw = r##"
selector = "#box"
"##;
    let rule: Rule = toml::from_str(raw).unwrap();
    assert_eq!(rule.password_id_attribute, "data-password-key");
}

#[test]
fn env_name_mapping() {
    assert_eq!(env_name_for_alias("blog"), "SITE_ENCRYPT_PASSWORDS_BLOG");
    assert_eq!(env_name_for_alias("my-blog"), "SITE_ENCRYPT_PASSWORDS_MY_BLOG");
    assert_eq!(env_name_for_alias("team.a"), "SITE_ENCRYPT_PASSWORDS_TEAM_A");
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
    let n = redact_feed_file(&path, "LOCKED", &files, false).unwrap();
    assert_eq!(n, 1);
    let out = fs::read_to_string(&path).unwrap();
    assert!(!out.contains("hidden body"));
    assert!(!out.contains("hidden summary"));
    assert!(out.contains("LOCKED"));
    assert!(out.contains("public body"));
    // rerun is a no-op
    let n2 = redact_feed_file(&path, "LOCKED", &files, false).unwrap();
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
    let n = redact_feed_file(&path, "LOCKED", &files, false).unwrap();
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
                class_name: "site-encrypt".into(),
                ui: UiStrings::default(),
            },
            feeds: FeedsConfig::default(),
            passwords: HashMap::from([("k1".to_string(), Secret("pw".to_string()))]),
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
                class_name: "site-encrypt".into(),
                ui: UiStrings::default(),
            },
            feeds: FeedsConfig::default(),
            passwords: passwords
                .iter()
                .map(|(k, v)| (k.to_string(), Secret(v.to_string())))
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

#[test]
fn missing_config_error_guides() {
    let err = read_config(Path::new("definitely-not-here-12345.toml")).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("--config"), "{msg}");
    assert!(msg.contains("definitely-not-here-12345.toml"), "{msg}");
}

#[test]
fn secret_never_prints() {
    assert_eq!(format!("{:?}", Secret("hunter2".to_string())), "***");
    let config = test_config(&[("k", "hunter2")]);
    assert!(!format!("{config:?}").contains("hunter2"));
}

// Env-mutating tests share one process-global namespace, so they take
// this lock to stay serial while the rest of the suite runs in parallel.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn set_env(name: &str, value: &str) {
    unsafe { std::env::set_var(name, value) };
}

fn remove_env(name: &str) {
    unsafe { std::env::remove_var(name) };
}

#[test]
fn env_password_overrides_toml() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_PASSWORDS_ENVTEST1", "from-env");
    let mut config = test_config(&[("envtest1", "from-toml")]);
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(&*config.passwords["envtest1"], "from-env");
    remove_env("SITE_ENCRYPT_PASSWORDS_ENVTEST1");
}

#[test]
fn env_password_provides_missing_alias() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_PASSWORDS_ENVTEST2", "only-env");
    let mut config = test_config(&[]);
    assert!(config.passwords.is_empty());
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(&*config.passwords["envtest2"], "only-env");
    remove_env("SITE_ENCRYPT_PASSWORDS_ENVTEST2");
}

#[test]
fn empty_env_value_is_ignored() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_PASSWORDS_ENVTEST3", "   ");
    let mut config = test_config(&[("envtest3", "keep-me")]);
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(config.passwords.len(), 1);
    assert_eq!(&*config.passwords["envtest3"], "keep-me");
    remove_env("SITE_ENCRYPT_PASSWORDS_ENVTEST3");
}

#[test]
fn env_overrides_scalars() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_ITERATIONS", "100000");
    set_env("SITE_ENCRYPT_FEED_PLACEHOLDER", "locked!");
    let mut config = test_config(&[]);
    config.encryption.iterations = 600_000;
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(config.encryption.iterations, 100_000);
    assert_eq!(config.feeds.placeholder, "locked!");
    remove_env("SITE_ENCRYPT_ITERATIONS");
    remove_env("SITE_ENCRYPT_FEED_PLACEHOLDER");
}

#[test]
fn env_bulk_passwords() {
    let _guard = env_lock();
    set_env(
        "SITE_ENCRYPT_PASSWORDS",
        "bulktest1 = \"pw1\"\nbulktest2 = \"pw2\"\n\"bulk-test3\" = \"pw3\"\n",
    );
    let mut config = test_config(&[]);
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(&*config.passwords["bulktest1"], "pw1");
    assert_eq!(&*config.passwords["bulktest2"], "pw2");
    // bulk keys are exact (TOML quoting), so any charset works
    assert_eq!(&*config.passwords["bulk-test3"], "pw3");
    remove_env("SITE_ENCRYPT_PASSWORDS");
}

#[test]
fn env_password_precedence_single_over_bulk_over_file() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_PASSWORDS", "envtest4 = \"from-bulk\"\n");
    set_env("SITE_ENCRYPT_PASSWORDS_ENVTEST4", "from-single");
    let mut config = test_config(&[("envtest4", "from-toml")]);
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(&*config.passwords["envtest4"], "from-single");
    remove_env("SITE_ENCRYPT_PASSWORDS_ENVTEST4");

    // bulk beats file when no per-alias var is set
    let mut config = test_config(&[("envtest4", "from-toml")]);
    apply_env_overrides(&mut config).unwrap();
    assert_eq!(&*config.passwords["envtest4"], "from-bulk");
    remove_env("SITE_ENCRYPT_PASSWORDS");
}

#[test]
fn invalid_env_bulk_is_an_error() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_PASSWORDS", "not valid toml [[[");
    let mut config = test_config(&[]);
    let err = apply_env_overrides(&mut config).unwrap_err();
    assert!(
        err.to_string().contains("SITE_ENCRYPT_PASSWORDS"),
        "unexpected error: {err:#}"
    );
    remove_env("SITE_ENCRYPT_PASSWORDS");
}

#[test]
fn invalid_env_iterations_is_an_error() {
    let _guard = env_lock();
    set_env("SITE_ENCRYPT_ITERATIONS", "not-a-number");
    let mut config = test_config(&[]);
    let err = apply_env_overrides(&mut config).unwrap_err();
    assert!(
        err.to_string().contains("SITE_ENCRYPT_ITERATIONS"),
        "unexpected error: {err:#}"
    );
    remove_env("SITE_ENCRYPT_ITERATIONS");
}

#[test]
fn self_contained_mode_injects_unlock_ui() {
    let document = parse_doc(
        "<!DOCTYPE html><html><body>\
        <div id=\"box\" data-password-key=\"k1\" data-hint=\"pet name\"><p>secret</p></div>\
        </body></html>",
    );
    let rule = Rule {
        selector: "#box".into(),
        password_id_attribute: default_password_id_attribute(),
        hint_attribute: Some("data-hint".into()),
        content_selector: None,
    };
    let config = test_config(&[("k1", "pw")]);
    let node = document.select_first("#box").unwrap().as_node().clone();
    assert!(encrypt_node(&node, &rule, &config, &document).unwrap());
    let html = serialize_node(&node).unwrap();
    assert!(html.contains("data-site-encrypt-ciphertext"), "{html}");
    assert!(html.contains("pet name"), "{html}"); // hint rendered
    assert!(html.contains("__form"), "{html}"); // unlock form injected
    assert!(!html.contains("<p>secret</p>"), "{html}"); // plaintext gone
    assert!(!html.contains("data-password-key"), "{html}"); // alias removed
    assert!(!html.contains("data-hint"), "{html}"); // hint attr removed
    // re-running on processed output fails loudly (the alias is gone, and
    // the payload lives on the injected inner div) instead of encrypting
    // a second time — rebuild from clean and re-run.
    let err = encrypt_node(&node, &rule, &config, &document).unwrap_err();
    assert!(
        err.to_string().contains("missing password attribute"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn unknown_password_id_error_suggests_env() {
    let document = parse_doc(
        "<!DOCTYPE html><html><body>\
        <div id=\"box\" data-password-key=\"blog\"></div>\
        </body></html>",
    );
    let rule = test_rule(None);
    let config = test_config(&[]);
    let node = document.select_first("#box").unwrap().as_node().clone();
    let err = encrypt_node(&node, &rule, &config, &document).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("SITE_ENCRYPT_PASSWORDS_BLOG"), "unexpected error: {msg}");
}
