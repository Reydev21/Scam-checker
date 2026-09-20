# ScamCheck Advanced

A responsive Python Flask prototype following the supplied fraud-risk flowchart.

## Features
- Scam Scanner for SMS, email, website text and receipts
- Image upload with preview, drag/drop, mobile camera support and OCR
- URL/domain red-flag analysis
- Advanced Article Checker with:
  - title, author, date and source URL inputs
  - clickbait/sensational language checks
  - attribution/source language checks
  - citation/reference signals
  - article length/readability signals
  - source-domain heuristics
  - structured JSON output
- Responsive UI for desktop and mobile
- Risk score and recommendation

## Install
Python 3.10+ recommended.

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    copy .env.example .env

## Run

    python app.py

Open http://127.0.0.1:5000

For Supabase, copy `.env.example` to `.env` and fill in `SUPABASE_URL`,
`SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` from the Supabase project
API settings. The service-role key is backend-only and must never be exposed in
templates, JavaScript, or client-side configuration.

The ready-to-run database schema is in `supabase_schema.sql`. Run it in the
Supabase Dashboard SQL Editor before connecting the Flask data layer.
After setting the Supabase variables and running the schema, migrate the
existing local JSON data once with:

    python migrate_json_to_supabase.py

After migration, the Flask app reads and writes users, audit logs, blocked IPs,
password reset tokens, and admin backup snapshots through Supabase. The schema
also includes scan results, OAuth identities, login attempts, threat events,
vulnerability scans, maintenance runs, system settings, notifications, and
file upload metadata for the remaining app modules.

The administrator console is intentionally not linked from the public pages. Open
`http://127.0.0.1:5000/admin/login` directly and sign in with administrator
credentials to access it. Configure `SCAMCHECK_SECRET_KEY`,
`SCAMCHECK_ADMIN_EMAIL`, and `SCAMCHECK_ADMIN_PASSWORD_HASH` as deployment
environment variables; administrator credentials are not stored in the source
code. Generate the password hash with:

    python -c "import hashlib; print(hashlib.sha256(b'YOUR_PASSWORD').hexdigest())"

For password recovery, configure SMTP and the public URL:

    SCAMCHECK_PUBLIC_URL=https://your-domain.com
    SCAMCHECK_SMTP_HOST=smtp.gmail.com
    SCAMCHECK_SMTP_PORT=587
    SCAMCHECK_SMTP_USER=your-gmail-address@gmail.com
    SCAMCHECK_SMTP_PASSWORD=<16-character-gmail-app-password>
    SCAMCHECK_SMTP_FROM=your-gmail-address@gmail.com

Enable 2-Step Verification on the Gmail account, then create an App Password
under Google Account > Security > App passwords. Do not use the normal Gmail
password and do not commit the App Password to source control.

Admins can edit a registered user's name or set a new password from the User
Directory tab. The deployment-level administrator password is changed by
updating `SCAMCHECK_ADMIN_PASSWORD_HASH` in the deployment secret settings.

Social login requires creating OAuth applications in Google Cloud Console,
Meta for Developers, and GitHub Developer Settings. Set each provider's
client ID and secret as deployment environment variables:

    SCAMCHECK_GOOGLE_CLIENT_ID=...
    SCAMCHECK_GOOGLE_CLIENT_SECRET=...
    SCAMCHECK_FACEBOOK_CLIENT_ID=...
    SCAMCHECK_FACEBOOK_CLIENT_SECRET=...
    SCAMCHECK_GITHUB_CLIENT_ID=...
    SCAMCHECK_GITHUB_CLIENT_SECRET=...

Register these exact callback URLs with each provider:

    https://your-domain.com/auth/google/callback
    https://your-domain.com/auth/facebook/callback
    https://your-domain.com/auth/github/callback

For local testing, replace `https://your-domain.com` with
`http://127.0.0.1:5000`. Do not commit OAuth secrets to the repository.

## OCR
Pillow and pytesseract are included. On Windows, pytesseract normally requires the Tesseract OCR application to be installed separately and available on PATH. If OCR is unavailable, the text checker still works.

## Article checker limitation
The Article Checker evaluates credibility signals. It does NOT prove that an article is fake or that a claim is true/false. A real fact-checking system should verify claims against independent sources and reliable databases.

## Project structure

scam_checker_app/
  app.py
  requirements.txt
  README.md
  templates/
    index.html
  static/
    app.js
    style.css
 audit_log.json
Username / Admin Email: admin@scamcheck.ai
Password: ScamCheckAdmin#2026!