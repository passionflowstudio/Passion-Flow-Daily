# Passion Flow Daily — website

This is the **Passion Flow Daily** website repo. It is the landing page first.

The iPhone app lives in a separate repo and should not be edited from here.

## What’s here

- `index.html` — public landing page (cream paper, cocoa type, five app pastels)
- `app.html` — existing web app, saved for later
- `privacy.html`, `terms.html`, `support.html` — App Store legal and support pages
- `netlify/` — Stripe functions already in this project
- `assets/` — app icon, hero screen recording, and poster

## Live product

- Site: [passionflowdaily.com](https://passionflowdaily.com)
- iPhone: [Passion Flow Daily on the App Store](https://apps.apple.com/us/app/passion-flow-daily/id6778534847)

Web and desktop come after the landing page.

## Run locally

```bash
python3 -m http.server 43127
```

Then open [http://127.0.0.1:43127](http://127.0.0.1:43127).

## Deploy

This folder deploys to Netlify the same way as before (`netlify.toml` publish = `.`).
