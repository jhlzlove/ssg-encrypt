# site-encrypt

Generator-agnostic static HTML post-processor for password-protected content. It runs **after** your static-site generator (Zola, Hugo, or any other) builds, encrypting marked nodes in-place before deployment.

```
SSG build  →  site-encrypt post-process  →  deploy
```

## Features

- **AES-256-GCM** authenticated encryption with **PBKDF2-HMAC-SHA256** key derivation.
- Fresh random 128-bit salt and 96-bit nonce for every encrypted node.
- Two operating modes: **split-UI** (theme provides its own unlock UI) and **self-contained** (generic unlock form injected).
- **Feed redaction** — Atom/RSS entries pointing to encrypted pages get their body replaced with a placeholder, so ciphertext never leaks through syndication.
- Passwords live only in local build-time config; they are never emitted to the output site.

## Security model

- Passwords are read from the local config file and never appear in the generated HTML.
- Each encryption uses a unique random salt and nonce.
- This is **not DRM** — anyone who decrypts content can copy the plaintext. It protects against casual inspection and search-engine indexing, not a determined attacker with the ciphertext.

## Requirements

Rust 1.98+. The included `rust-toolchain.toml` pins the current stable patch release.

## Usage

```bash
cargo run -- --input public
```

`--config` defaults to `encrypt.toml`. Use `--dry-run` to scan and validate without writing files, or `--check` to only validate the config and CSS selectors (touches nothing on disk and needs no passwords — ideal for PR checks without secrets).

## GitHub Action

Use the prebuilt binary straight from this repo's releases — passwords come from secrets via env, so the committed config holds no secrets:

```yaml
# Pull requests: validate without secrets (safe on forks, too)
- uses: <owner>/site-encrypt@v1
  with:
    check: "true"

# Deploy builds: encrypt after the SSG build, before deploy
- uses: <owner>/site-encrypt@v1
  with:
    input: public        # default
    config: encrypt.toml # default
  env:
    # one secret holding many passwords (TOML `alias = "password"` lines)
    SITE_ENCRYPT_PASSWORDS: ${{ secrets.SITE_PASSWORDS }}
    # …or one env var per password (wins over the bulk var)
    SITE_ENCRYPT_PASSWORDS_BLOG: ${{ secrets.BLOG_PASSWORD }}
```

Full example with Zola:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build site
        run: zola build
      - uses: <owner>/site-encrypt@v1
        env:
          SITE_ENCRYPT_PASSWORDS_BLOG: ${{ secrets.BLOG_PASSWORD }}
      - name: Deploy
        run: # ... your deploy step (e.g. peaceiris/actions-gh-pages)
```

## Configuration

Copy `encrypt.example.toml` to `encrypt.toml` (git-ignored — never commit real passwords) and adjust:

```toml
[[scanner.rules]]
selector = "#encryptedBox"
content_selector = "#articleContent"

[encryption]
iterations = 600000

[feeds]
enabled = true
placeholder = "本文已加密，前往原文解锁后阅读。"

[passwords]
blog = "replace-this"
```

See the full reference below. Every value also has an env override (next section), so CI can leave `[passwords]` empty.

### Environment overrides

Every variable is optional: set-and-non-empty wins over the TOML value. Empty values are ignored (so `VAR: ""` never blanks out file config).

| Variable | Overrides |
|---|---|
| `SITE_ENCRYPT_PASSWORDS` | **Bulk passwords**: TOML `alias = "password"` lines (one secret for many passwords). Quoted keys support any charset (`"my-alias" = "…"`) |
| `SITE_ENCRYPT_PASSWORDS_<ALIAS>` | Password for alias `<ALIAS>` (uppercased, non-alphanumeric → `_`; e.g. `blog` → `SITE_ENCRYPT_PASSWORDS_BLOG`). Env-settable aliases should stick to `[a-z0-9_]+`; anything else keeps living in `[passwords]` or the bulk var. |
| `SITE_ENCRYPT_ITERATIONS` | `encryption.iterations` |
| `SITE_ENCRYPT_FEED_PLACEHOLDER` | `feeds.placeholder` |
| `SITE_ENCRYPT_PASSWORD_LABEL` / `SITE_ENCRYPT_SUBMIT_LABEL` / `SITE_ENCRYPT_NOSCRIPT_TEXT` | `[output.ui]` strings |

## Theme integration

### Markup contract

Add `data-site-encrypt="true"` and a password-id attribute to any element you want encrypted:

```html
<article data-site-encrypt="true" data-password-key="blog">
  <h1>Secret article</h1>
  <p>This body will be encrypted after the SSG runs.</p>
</article>
```

After processing, the element's children are replaced by an unlock UI (self-contained mode) or the payload attributes are written onto the matched node (split-UI mode). The companion `site-decrypt.js` discovers and decrypts these at runtime.

### Browser runtime

Copy `web/site-encrypt.js` into your theme's assets and load it on pages with encrypted content:

```html
<script src="/assets/site-encrypt.js" defer></script>
```

The CLI intentionally does **not** inject this script — themes have different asset pipelines and CSP policies.

### Discovery contract (fixed attribute names)

| Attribute | Meaning |
|---|---|
| `data-site-encrypt="1"` | Payload root marker |
| `data-site-encrypt-version` | Format version (currently `"1"`) |
| `data-site-encrypt-kdf` | KDF identifier (`pbkdf2-sha256`) |
| `data-site-encrypt-iterations` | PBKDF2 iterations (>= 100 000) |
| `data-site-encrypt-salt` | Base64url salt |
| `data-site-encrypt-nonce` | Base64url nonce |
| `data-site-encrypt-ciphertext` | Base64url ciphertext |
| `data-site-encrypt-target` | *(optional)* CSS selector for split-UI mode |

On successful decryption the browser runtime dispatches `site-encrypt:unlocked` on `document` with `detail { root, target }` — use it to re-initialize syntax highlighting, players, or other components.

## Configuration reference

### `[scanner]`

| Key | Default | Description |
|---|---|---|
| `extensions` | `["html"]` | File extensions to process. |
| `exclude` | `[]` | Relative paths to skip. Forward slashes; supports `*`, `?`, `**`. e.g. `["404.html", "print/**"]`. |
| `rules` | *(required)* | Array of encryption rules (see below). |

### `[[scanner.rules]]`

| Key | Required | Default | Description |
|---|---|---|---|
| `selector` | yes | — | CSS selector for the node carrying the password id. |
| `password_id_attribute` | no | `"data-password-key"` | Attribute on the matched node holding the password alias (maps to `[passwords]` / `SITE_ENCRYPT_PASSWORDS_<ALIAS>`). |
| `hint_attribute` | no | — | Attribute holding a password hint (displayed in self-contained mode). |
| `content_selector` | no | CSS selector of the node whose children should be encrypted instead. When set, operates in **split-UI mode**: payload attributes land on the matched node, no unlock UI is injected, and `data-site-encrypt-target` is written automatically. |

**Two modes at a glance:**

- **Split-UI mode** (recommended — theme provides its own unlock UI): set both `selector` (the lock panel / trigger) and `content_selector` (the article body). The body is encrypted, the payload is written onto the lock panel, and no generic UI is injected.
- **Self-contained mode** (bare pages without custom UI): set only `selector`. The matched node's children are encrypted and a generic unlock form is injected in their place.

### `[encryption]`

| Key | Default | Env | Description |
|---|---|---|---|
| `iterations` | `600000` | `SITE_ENCRYPT_ITERATIONS` | PBKDF2 iteration count. Minimum 100 000 (enforced by both CLI and browser runtime). Only increase. |

### `[output]`

| Key | Default | Description |
|---|---|---|
| `class_name` | `"site-encrypt"` | CSS class prefix for the injected unlock form (self-contained mode only). |
| `[output.ui]` | see below | Localized strings for the injected unlock form. |

`password-id` and hint attributes are always removed after encryption — they served their purpose at build time and are never shipped.

#### `[output.ui]` (self-contained mode only)

| Key | Default | Env |
|---|---|---|
| `password_label` | `"Password"` | `SITE_ENCRYPT_PASSWORD_LABEL` |
| `submit_label` | `"Unlock"` | `SITE_ENCRYPT_SUBMIT_LABEL` |
| `noscript_text` | `"JavaScript is required to decrypt this content."` | `SITE_ENCRYPT_NOSCRIPT_TEXT` |

### `[feeds]`

Redacts Atom/RSS feed entries that link to encrypted pages. Matching is **path-suffix based** (scheme/host ignored, leading segments peeled until something matches), so localhost preview builds, root deployments and subpath deployments (e.g. `example.com/docs`) redact identically with no extra configuration. Fail-closed: a same-tail public page redacts too — placeholder instead of body, never a leak.

| Key | Default | Env | Description |
|---|---|---|---|
| `enabled` | `false` | — | Enable feed redaction. |
| `paths` | `["**/atom.xml", "**/rss.xml", "**/feed.xml", "**/index.xml"]` | — | Glob patterns for feed files. |
| `placeholder` | `"This post is encrypted; open the original page to unlock it."` | `SITE_ENCRYPT_FEED_PLACEHOLDER` | Replacement text for encrypted entries. |

> **Note:** planet-style feeds that aggregate external articles should be excluded via `scanner.exclude`.

### `[passwords]`

Map of password aliases to real passwords. The alias appears in your HTML; the real password lives **only** in this config file (local dev) or in env vars (CI). May be left empty when all passwords come from env. Never put real passwords in article front-matter or commit them to a public repo.

```toml
[passwords]
blog = "a-strong-password-here"
private = "another-password"
```

On CI, each alias maps to one secret (see [Environment overrides](#environment-overrides)) — either one secret per password, or a single secret holding TOML lines:

```yaml
env:
  SITE_ENCRYPT_PASSWORDS_BLOG: ${{ secrets.BLOG_PASSWORD }}
  SITE_ENCRYPT_PASSWORDS_PRIVATE: ${{ secrets.PRIVATE_PASSWORD }}
  # or equivalently:
  # SITE_ENCRYPT_PASSWORDS: ${{ secrets.SITE_PASSWORDS }}
  # where SITE_PASSWORDS contains:
  #   blog = "…"
  #   private = "…"
```

## License

MIT
