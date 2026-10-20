# carrutherslaw.ca - static site

Static copy of the WordPress (WP Engine) site for Carruthers Law, Calgary, plus one small PHP endpoint
that replaces the Elementor / Clio Grow form handlers. No CMS, no database; PHP only in `intake/submit.php`.

Converted 2026-10-20 from the live site (48 sitemap URLs, URLs frozen, absolute URLs throughout).

## Layout

- `public/` - the deployable webroot (Plesk docroot = `carrutherslaw-static/public`).
  - `.htaccess` - www to apex 301, directory listing off, 404 page, old WordPress endpoints.
  - `intake/submit.php` - form handler (PHP 8.4, no dependencies): honeypot `ref2`, 3-second time trap,
    per-IP rate limit, reCAPTCHA v2 server verify, Mailgun send, CSV lead log.
  - `contact/thank-you/` - success page. Errors return to the posting page with `?error=fields|captcha|send`.
  - `robots.txt`, `sitemap_index.xml` and the child sitemaps - copied from the live Yoast output.
- `private/intake-config.example.php` - shape of the real config. The real `intake-config.php` lives on the
  server at `<vhost-root>/private/intake-config.php` (mode 600), outside git and outside the webroot.
- `scripts/predeploy-audit.sh` - PDSP audit (managed copy, byte-identical to site-register `pdsp/`; do not edit).
- `scripts/lineage-check.sh` + `lineage-denylist.txt` - no other client's identity may ship.

## Build token to replace before deploy

`data-sitekey="RECAPTCHA_SITE_KEY"` appears on the pages carrying the form. Replace with the real reCAPTCHA v2
site key (second rc/ PR). Gate: `grep -rc RECAPTCHA_SITE_KEY public | grep -v ':0'` must print nothing.

## Editing

No CMS. A copy change is an edit to the HTML on an `rc/*` branch, audited with `scripts/predeploy-audit.sh`,
merged by a human, then fetched and deployed by Plesk Git on the server (`ext git --fetch` then `--deploy`).
