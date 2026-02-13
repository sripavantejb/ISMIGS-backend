# ISMIGS backend (admin panel API)

Full admin-panel backend: MongoDB (sector recipients, email logs, settings), JWT auth, Nodemailer.

## Setup

1. `cd backend && npm install`
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `JWT_SECRET`, optional SMTP credentials, and **`OPENAI_API_KEY`** (required for test emails and digest: sector LinkedIn posts; get one at https://platform.openai.com/api-keys). Optional fallback **`OPEN_AI_API_KEY_ADMIN`** is used when the primary key is unset or when a request returns 401.
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
- **POST /api/send-sector-email** – send test/real email (single sector or `sector_key: "all"`). Test emails require `OPENAI_API_KEY` (sector LinkedIn post). Optional body: `insights[]`, `warnings[]` for digest (also requires `OPENAI_API_KEY`).

## Deploying (e.g. Vercel)

Set these **Environment Variables** in your backend project (e.g. ismigs-backend on Vercel):

- **MONGODB_URI** – required
- **JWT_SECRET** – required
- **OPENAI_API_KEY** – required for test emails and digest (sector LinkedIn posts). Create at https://platform.openai.com/api-keys and add it in Vercel: Project → Settings → Environment Variables → add `OPENAI_API_KEY` for Production (and Preview if needed), then redeploy. Optional **OPEN_AI_API_KEY_ADMIN** is used when the primary key is unset or when a request returns 401.

- **FRONTEND_BASE_URL** – **required in production.** Set to your deployed frontend URL (e.g. `https://ismigs-frontend.vercel.app`). Without it, Yes/No redirects return 503 and users cannot reach the decision page after clicking the email link.

**Vercel checklist for Gmail Yes/No links:**
- **MONGODB_URI** – Must be set on Vercel; use the same DB as where disclosure emails are sent.
- **BACKEND_PUBLIC_URL** – Public backend URL for Yes/No links (Vercel uses VERCEL_URL if unset).
- **FRONTEND_BASE_URL** – Frontend URL for redirects after approval.
- **DECISION_TOKEN_TTL_HOURS** – Optional; default 168 (7 days). Link validity in hours.

When using the deployed frontend for the admin panel, ensure the frontend does not set `VITE_API_URL` to localhost so the admin panel and the email Yes/No link use the same backend; then the "LinkedIn post approval status" table will show "Approved for LinkedIn" after an admin clicks Yes.

Optional: SMTP_*, APPROVAL_BASE_URL, LINKEDIN_WEBHOOK_URL, DECISION_TOKEN_TTL_HOURS.

## Data (MongoDB, database: ismigs)

- **sector_recipients** – sector_key, display_name, emails[], label, enabled, cc[], bcc[]
- **email_logs** – sector_key, recipient, subject, sent_at, success, error_message
- **admin_settings** – key, value (notifications_enabled, default_from)
