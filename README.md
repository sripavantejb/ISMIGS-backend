# ISMIGS backend (admin panel API)

Full admin-panel backend: MongoDB (sector recipients, email logs, settings), JWT auth, Nodemailer.

## Setup

1. `cd backend && npm install`
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `JWT_SECRET`, optional SMTP credentials, and optional `OPENAI_API_KEY` (for email digest: LinkedIn-style post from insights + warnings).
3. Run `npm run dev` (or `npm start`).

Server runs on port 3001. The frontend Vite app proxies `/api` to this server in development.

## Auth

- **POST /api/auth/login** – `{ username, password }` → `{ token }`. Default: admin / admin123.
- All other `/api/*` require `Authorization: Bearer <token>`.
- **GET /api/auth/me** – returns `{ user }` if token valid.

## API (all under /api, auth required except login)

- **GET/PUT /api/sector-recipients** – list / upsert sector recipients
- **GET /api/sector-recipients/export** – CSV export
- **POST /api/sector-recipients/import** – CSV/JSON import
- **GET/PATCH /api/settings** – admin settings (notifications_enabled, default_from)
- **POST /api/settings/smtp-test** – send test email
- **GET /api/email-logs** – list email send history
- **POST /api/send-sector-email** – send test/real email (single sector or `sector_key: "all"`). Optional body: `insights[]`, `warnings[]` to send a LinkedIn-style digest (requires `OPENAI_API_KEY`).

## Data (MongoDB, database: ismigs)

- **sector_recipients** – sector_key, display_name, emails[], label, enabled, cc[], bcc[]
- **email_logs** – sector_key, recipient, subject, sent_at, success, error_message
- **admin_settings** – key, value (notifications_enabled, default_from)
