# Browser runtime

Copy `site-encrypt.js` into the theme/site assets and load it on pages containing encrypted content:

```html
<script src="/assets/site-encrypt.js" defer></script>
```

The CLI intentionally does not inject the script because Zola/Hugo themes have different asset pipelines and CSP policies.
