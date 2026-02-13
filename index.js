/**
 * ISMIGS Node.js backend: MongoDB (sector recipients, email logs, settings), JWT auth.
 * All email is sent via Nodemailer (SMTP when configured, or Ethereal in dev).
 * Run from backend folder: npm run dev
 */
import "dotenv/config";
import crypto from "crypto";
import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";
import { generateLinkedInPost } from "./services/energyLinkedIn.js";
import { fetchCommodityStats, listCommodities } from "./services/energyData.js";

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "ismigs-dev-secret-change-in-production";
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://myselfyourstej_db_user:ismigs@cluster0.eq96ml6.mongodb.net/?appName=Cluster0";

let db = null;
const DB_NAME = "ismigs";

async function connectDb() {
  const uri = process.env.MONGODB_URI || MONGODB_URI;
  const client = await MongoClient.connect(uri);
  db = client.db(DB_NAME);
  await db.collection("admin_settings").createIndex({ key: 1 }, { unique: true }).catch(() => {});
  await db.collection("sector_recipients").createIndex({ sector_key: 1 }, { unique: true }).catch(() => {});
  await db.collection("admin_decisions").createIndex({ token: 1 }, { unique: true }).catch(() => {});
  await db.collection("admin_decisions").createIndex({ expires_at: 1 }).catch(() => {});
  await db.collection("sector_alerts_log").createIndex({ commodity: 1, sector: 1, sent_at: 1 }).catch(() => {});
  return db;
}

function getDb() {
  return db;
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth && auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

const smtpHost = process.env.SMTP_HOST || process.env.SMTP_HOSTNAME;
const smtpPort = parseInt(process.env.SMTP_PORT || "587", 10);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS || process.env.SMTP_PASSWORD;
const envSmtpFrom = process.env.SMTP_FROM || smtpUser;

async function getSettings() {
  const database = getDb();
  if (!database) return { notifications_enabled: true, default_from: null };
  const col = database.collection("admin_settings");
  const docs = await col.find({}).toArray();
  const map = {};
  docs.forEach((r) => { map[r.key] = r.value; });
  return {
    notifications_enabled: map.notifications_enabled !== false,
    default_from: map.default_from ?? null,
  };
}

function getFrom(settings) {
  return (settings && settings.default_from) || envSmtpFrom;
}

async function insertEmailLog(sector_key, recipient, subject, success, error_message) {
  const database = getDb();
  if (!database) return;
  await database.collection("email_logs").insertOne({
    sector_key,
    recipient,
    subject: subject || "",
    sent_at: new Date(),
    success: !!success,
    error_message: error_message || null,
  });
}

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

async function generateLinkedInDigest(insights, warnings) {
  if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY required for digest emails");
  const insightList = Array.isArray(insights) ? insights.filter((s) => String(s).trim()) : [];
  const warningList = Array.isArray(warnings) ? warnings.filter((s) => String(s).trim()) : [];
  const hasContent = insightList.length > 0 || warningList.length > 0;
  if (!hasContent) throw new Error("Provide at least one insight or warning for the digest");
  const userContent = [
    insightList.length ? `Top insights:\n${insightList.map((i) => `• ${i}`).join("\n")}` : "",
    warningList.length ? `Critical warnings:\n${warningList.map((w) => `• ${w}`).join("\n")}` : "",
  ]
    .filter(Boolean)
    .join("\n\n");
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a macro intelligence writer. Turn the given top insights and critical warnings from a government macro dashboard into a single LinkedIn-style post. Use one short hook line, then 2-3 short paragraphs or bullet points. Be professional, data-driven, and suitable for policymakers and analysts. Maximum 300 words. No hashtags.",
        },
        { role: "user", content: userContent },
      ],
      max_tokens: 400,
      temperature: 0.4,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenAI API error: ${res.status} ${errText.slice(0, 200)}`);
  }
  const data = await res.json();
  const text = data.choices?.[0]?.message?.content?.trim();
  if (!text) throw new Error("OpenAI returned no content");
  return text;
}

function getSectorType(sector_key) {
  if (!sector_key || typeof sector_key !== "string") return "custom";
  const idx = sector_key.indexOf(":");
  if (idx <= 0) return "custom";
  const type = sector_key.slice(0, idx).toLowerCase();
  if (["custom", "energy", "wpi", "iip", "gva"].includes(type)) return type;
  return "custom";
}

function extractHashtagsFromText(text) {
  const tags = [];
  const re = /#[\w]+/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[0]);
  return tags;
}

async function generateSectorSamplePost(sector_key, displayName) {
  if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY required for test emails");
  const sectorType = getSectorType(sector_key);
  const systemPrompt =
    "You are a macro intelligence writer for ISMIGS (India State Macro Intelligence). Subscribers receive sector-specific notifications and updates on the ISMIGS dashboard. Write a short LinkedIn-style post that summarizes the kind of notifications and updates this sector sees: use the sector type and name to tailor content (e.g. IIP = industrial production indices and growth; WPI = wholesale price inflation; Energy = supply, consumption, and commodity prices; GVA = industry-wise GVA; Custom = general macro and policy updates). Be professional, data-driven, and suitable for policymakers and analysts. Maximum 150 words. End with 5-8 relevant hashtags (e.g. #ISMIGS #IndiaEconomy #Manufacturing).";
  const userPrompt = `Sector: ${displayName}. Sector type: ${sectorType}. Write a LinkedIn post summarizing the type of notifications and updates this sector would see on the ISMIGS dashboard.`;
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      max_tokens: 250,
      temperature: 0.4,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenAI API error: ${res.status} ${errText.slice(0, 200)}`);
  }
  const data = await res.json();
  const rawText = data.choices?.[0]?.message?.content?.trim();
  if (!rawText) throw new Error("OpenAI returned no content");
  const hashtags = extractHashtagsFromText(rawText);
  const linkedin_post_text = rawText.replace(/#[\w]+/g, "").replace(/\n{3,}/g, "\n\n").trim();
  return { linkedin_post_text: linkedin_post_text || rawText, hashtags };
}

// ---------- Energy disclosure: AdminDecisions, n8n, confirmation email ----------

const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL;
const CRON_SECRET = process.env.CRON_SECRET || "change-me-cron-secret";
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || process.env.VITE_APP_URL || "http://localhost:5173";

function getDecisionRedirectUrl(result) {
  const base = FRONTEND_BASE_URL.replace(/\/$/, "");
  return `${base}/admin/decision?result=${result}`;
}

function getBackendPublicUrl() {
  return (process.env.BACKEND_PUBLIC_URL || process.env.API_BASE_URL || "").replace(/\/$/, "") || `http://localhost:${process.env.PORT || 3001}`;
}

function appendConfirmationBlock(linkedin_post_text, hashtags, token) {
  const base = getBackendPublicUrl();
  const approveLink = `${base}/api/admin/decision?token=${token}&type=approve`;
  const rejectLink = `${base}/api/admin/decision?token=${token}&type=reject`;
  const hashtagStr = Array.isArray(hashtags) ? hashtags.join(" ") : (hashtags || "");
  const textSuffix =
    `\n\nHashtags: ${hashtagStr}\n\n---\nDo you want to post this on LinkedIn?\nYes: ${approveLink}\nNo: ${rejectLink}`;
  const htmlSuffix =
    `<p>Hashtags: ${hashtagStr}</p>` +
    `<p><strong>Do you want to post this on LinkedIn?</strong></p>` +
    `<p><a href="${approveLink}" style="display:inline-block;margin-right:12px;padding:8px 16px;background:#0a66c2;color:#fff;text-decoration:none;border-radius:6px;">Yes</a> <a href="${rejectLink}" style="display:inline-block;padding:8px 16px;background:#6c757d;color:#fff;text-decoration:none;border-radius:6px;">No</a></p>`;
  return { approveLink, rejectLink, textSuffix, htmlSuffix };
}

async function triggerN8nWebhook(decisionRecord) {
  if (!N8N_WEBHOOK_URL) {
    console.warn("N8N_WEBHOOK_URL not set; skipping webhook.");
    return;
  }
  const payload = {
    commodity: decisionRecord.commodity,
    production: decisionRecord.production,
    consumption: decisionRecord.consumption,
    import_dependency: decisionRecord.import_dependency,
    risk_score: decisionRecord.risk_score,
    projected_deficit_year: decisionRecord.projected_deficit_year,
    sector_impact: decisionRecord.sector_impact,
    linkedin_post_text: decisionRecord.linkedin_post_text,
    hashtags: decisionRecord.hashtags,
    approved_at: decisionRecord.responded_at ? new Date(decisionRecord.responded_at).toISOString() : new Date().toISOString(),
  };
  const doPost = async () => {
    const res = await fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`n8n webhook ${res.status}: ${await res.text()}`);
  };
  try {
    await doPost();
  } catch (err) {
    console.error("n8n webhook failed:", err.message);
    try {
      await doPost();
    } catch (retryErr) {
      console.error("n8n webhook retry failed:", retryErr.message);
      throw retryErr;
    }
  }
}

async function sendConfirmationEmail(adminEmail, postData, transport, fromAddr) {
  const database = getDb();
  const token = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 48 * 60 * 60 * 1000);
  const decision = {
    token,
    commodity: postData.commodity,
    linkedin_post_text: postData.linkedin_post_text,
    hashtags: Array.isArray(postData.hashtags) ? postData.hashtags : [postData.hashtags].filter(Boolean),
    status: "pending",
    created_at: now,
    expires_at: expiresAt,
    responded_at: null,
    production: postData.production,
    consumption: postData.consumption,
    import_dependency: postData.import_dependency,
    risk_score: postData.risk_score,
    projected_deficit_year: postData.projected_deficit_year,
    sector_impact: postData.sector_impact,
  };
  if (database) {
    await database.collection("admin_decisions").insertOne(decision);
  }
  const { textSuffix: confirmTextSuffix, htmlSuffix: confirmHtmlSuffix } = appendConfirmationBlock(postData.linkedin_post_text, postData.hashtags, token);

  const statsLines = postData.stats_summary
    ? [
        `Production: ${postData.stats_summary.production?.toLocaleString() ?? "—"}`,
        `Consumption: ${postData.stats_summary.consumption?.toLocaleString() ?? "—"}`,
        `Import dependency: ${postData.stats_summary.import_dependency_pct ?? "—"}%`,
        `Risk score: ${postData.stats_summary.risk_score ?? "—"}`,
        postData.stats_summary.projected_deficit_year ? `Projected deficit year: ${postData.stats_summary.projected_deficit_year}` : "",
        postData.stats_summary.sector_impact ? `Sector impact: ${postData.stats_summary.sector_impact}` : "",
      ].filter(Boolean)
    : [];
  const statsBlock = statsLines.length ? `\n\n--- Stats summary ---\n${statsLines.join("\n")}\n` : "";
  const text = `${postData.linkedin_post_text}\n${statsBlock}` + confirmTextSuffix;
  const html =
    `<p style="white-space:pre-wrap;">${postData.linkedin_post_text.replace(/\n/g, "<br>")}</p>` +
    (statsLines.length ? `<p><strong>Stats summary</strong><br>${statsLines.join("<br>")}</p>` : "") +
    confirmHtmlSuffix;

  await transport.sendMail({
    from: fromAddr,
    to: adminEmail,
    subject: `ISMIGS – Confirm LinkedIn post for ${postData.commodity}`,
    text,
    html,
  });
  return { token, expires_at: expiresAt };
}

// ---------- Auth (no requireAuth) ----------

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const u = typeof username === "string" ? username.trim() : "";
  const p = typeof password === "string" ? password : "";
  if (u === ADMIN_USERNAME && p === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { sub: "admin", iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    return res.json({ token });
  }
  return res.status(401).json({ error: "Invalid username or password." });
});

// Auth skipped for now – no JWT required on /api routes
// app.use("/api", requireAuth);

app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.user || "admin" });
});

// ---------- OpenAI proxy (for frontend Predictions / GVA impact) ----------

app.post("/api/openai/v1/chat/completions", async (req, res) => {
  const key = process.env.OPENAI_API_KEY;
  if (!key) {
    return res.status(503).json({ error: "OpenAI API key not configured." });
  }
  const body = req.body && typeof req.body === "object" ? req.body : {};
  try {
    const upstream = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify(body),
    });
    const text = await upstream.text();
    const contentType = upstream.headers.get("content-type") || "application/json";
    res.setHeader("Content-Type", contentType);
    res.status(upstream.status).send(text);
  } catch (e) {
    console.error("OpenAI proxy error:", e.message);
    res.status(502).json({ error: "Failed to reach OpenAI. Try again later." });
  }
});

// ---------- Sector recipients ----------

function safeToISOString(value) {
  if (value == null) return new Date().toISOString();
  try {
    const d = new Date(value);
    return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
  } catch {
    return new Date().toISOString();
  }
}

function safeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((e) => (e != null ? String(e).trim() : "")).filter(Boolean);
}

app.get("/api/sector-recipients", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  let rows;
  try {
    rows = await database.collection("sector_recipients").find({}).toArray();
  } catch (e) {
    console.error("GET /api/sector-recipients query failed", e);
    res.setHeader("X-Sector-Recipients-Error", "1");
    return res.status(200).json({});
  }
  const map = {};
  for (const row of rows) {
    try {
      const sectorKey = row && (row.sector_key != null) ? String(row.sector_key) : null;
      if (!sectorKey) continue;
      map[sectorKey] = {
        sector_key: sectorKey,
        display_name: row.display_name != null ? String(row.display_name) : sectorKey,
        emails: safeStringArray(row.emails),
        updated_at: safeToISOString(row.updated_at),
        label: row.label != null ? String(row.label) : null,
        enabled: row.enabled !== false,
        cc: safeStringArray(row.cc),
        bcc: safeStringArray(row.bcc),
      };
    } catch (rowErr) {
      console.warn("sector-recipients: skip invalid row", rowErr.message);
    }
  }
  res.json(map);
});

app.put("/api/sector-recipients", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  const { sector_key, display_name, emails, label, enabled, cc, bcc } = req.body || {};
  if (!sector_key || typeof display_name !== "string") {
    return res.status(400).json({ error: "Body must include sector_key and display_name." });
  }
  const list = Array.isArray(emails) ? emails.filter((e) => String(e).trim()) : [];
  const payload = {
    sector_key,
    display_name: display_name || sector_key,
    emails: list,
    updated_at: new Date().toISOString(),
    label: label != null ? String(label) : null,
    enabled: enabled !== false,
    cc: Array.isArray(cc) ? cc.filter((e) => String(e).trim()) : [],
    bcc: Array.isArray(bcc) ? bcc.filter((e) => String(e).trim()) : [],
  };
  try {
    await database.collection("sector_recipients").updateOne(
      { sector_key },
      { $set: payload },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/sector-recipients/export", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  try {
    const rows = await database.collection("sector_recipients").find({}).toArray();
    const header = "sector_key,display_name,emails\n";
    const body = rows
      .map((r) => {
        const emails = (r.emails || []).map((e) => `"${String(e).replace(/"/g, '""')}"`).join(";");
        return `${r.sector_key},"${(r.display_name || "").replace(/"/g, '""')}",${emails}`;
      })
      .join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=sector-recipients.csv");
    res.send(header + body);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/sector-recipients/import", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  let rows = req.body?.rows;
  if (!Array.isArray(rows)) {
    const raw = req.body?.csv || req.body?.body;
    if (typeof raw === "string") {
      const lines = raw.trim().split(/\r?\n/).filter(Boolean);
      rows = lines.slice(1).map((line) => {
        const parts = [];
        let cur = "";
        let inQuotes = false;
        for (let i = 0; i < line.length; i++) {
          const c = line[i];
          if (c === '"') inQuotes = !inQuotes;
          else if ((c === "," || c === "\t") && !inQuotes) {
            parts.push(cur.trim());
            cur = "";
          } else cur += c;
        }
        parts.push(cur.trim());
        const sector_key = parts[0] || "";
        const display_name = (parts[1] || "").replace(/^"|"$/g, "");
        const emailsStr = (parts[2] || "").replace(/^"|"$/g, "");
        const emails = emailsStr ? emailsStr.split(/[;,\n]/).map((e) => e.trim()).filter(Boolean) : [];
        return { sector_key, display_name, emails };
      });
    } else {
      return res.status(400).json({ error: "Body must include rows array or csv/body string." });
    }
  }
  const col = database.collection("sector_recipients");
  let ok = 0, err = 0;
  for (const r of rows) {
    if (!r.sector_key) continue;
    try {
      await col.updateOne(
        { sector_key: r.sector_key },
        {
          $set: {
            sector_key: r.sector_key,
            display_name: r.display_name ?? r.sector_key,
            emails: Array.isArray(r.emails) ? r.emails : [],
            updated_at: new Date().toISOString(),
          },
        },
        { upsert: true }
      );
      ok++;
    } catch (_) {
      err++;
    }
  }
  res.json({ ok, err, total: rows.length });
});

// ---------- Settings ----------

app.get("/api/settings", async (req, res) => {
  try {
    const settings = await getSettings();
    res.json(settings);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/settings", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  const { notifications_enabled, default_from } = req.body || {};
  const col = database.collection("admin_settings");
  try {
    if (typeof notifications_enabled === "boolean") {
      await col.updateOne(
        { key: "notifications_enabled" },
        { $set: { key: "notifications_enabled", value: notifications_enabled, updated_at: new Date().toISOString() } },
        { upsert: true }
      );
    }
    if (default_from !== undefined) {
      await col.updateOne(
        { key: "default_from" },
        { $set: { key: "default_from", value: default_from == null || default_from === "" ? null : default_from, updated_at: new Date().toISOString() } },
        { upsert: true }
      );
    }
    const settings = await getSettings();
    res.json(settings);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/settings/smtp-test", async (req, res) => {
  const to = req.body?.to;
  if (!to || typeof to !== "string") {
    return res.status(400).json({ error: "Body must include to (email string)." });
  }
  const toAddr = to.trim();
  try {
    if (smtpHost && smtpUser && smtpPass) {
      const settings = await getSettings();
      const from = getFrom(settings);
      const transport = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass },
      });
      await transport.sendMail({
        from,
        to: toAddr,
        subject: "ISMIGS SMTP test",
        text: "This is a test email from ISMIGS. SMTP is working.",
        html: "<p>This is a test email from ISMIGS. SMTP is working.</p>",
      });
      return res.json({ ok: true });
    }
    // Dev fallback: use Ethereal test account so the test "succeeds" without real SMTP
    const testAccount = await nodemailer.createTestAccount();
    const devTransport = nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: { user: testAccount.user, pass: testAccount.pass },
    });
    const info = await devTransport.sendMail({
      from: "ISMIGS Dev <noreply@ethereal.email>",
      to: toAddr,
      subject: "ISMIGS SMTP test (dev)",
      text: "This is a test email from ISMIGS (dev mode). No real SMTP configured; message is in Ethereal.",
      html: "<p>This is a test email from ISMIGS (dev mode). No real SMTP configured; message is in Ethereal.</p>",
    });
    const previewUrl = nodemailer.getTestMessageUrl(info) || null;
    res.json({ ok: true, dev: true, previewUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Email logs ----------

app.get("/api/email-logs", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const offset = parseInt(req.query.offset, 10) || 0;
  const sector_key = req.query.sector_key;
  try {
    let cursor = database.collection("email_logs").find(sector_key ? { sector_key } : {}).sort({ sent_at: -1 }).skip(offset).limit(limit);
    const data = await cursor.toArray();
    const out = data.map((doc) => ({
      id: doc._id.toString(),
      sector_key: doc.sector_key,
      recipient: doc.recipient,
      subject: doc.subject,
      sent_at: doc.sent_at ? new Date(doc.sent_at).toISOString() : null,
      success: doc.success,
      error_message: doc.error_message,
    }));
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Send sector email ----------

const ETHERAL_TIMEOUT_MS = 8000;

async function createEtherealTransport() {
  const testAccount = await nodemailer.createTestAccount();
  const transport = nodemailer.createTransport({
    host: testAccount.smtp.host,
    port: testAccount.smtp.port,
    secure: testAccount.smtp.secure,
    auth: { user: testAccount.user, pass: testAccount.pass },
  });
  const fromAddr = `ISMIGS Dev <${testAccount.user}>`;
  return { transport, fromAddr };
}

function createEtherealTransportWithTimeout() {
  return Promise.race([
    createEtherealTransport(),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Ethereal timeout")), ETHERAL_TIMEOUT_MS)
    ),
  ]);
}

async function sendOneSector(sector_key, bodyEmails, isTest, settings, transport, fromAddr) {
  let emails = Array.isArray(bodyEmails) ? bodyEmails.filter((e) => String(e).trim()) : [];
  let displayName = sector_key || "Sector";
  let cc = [];
  let bcc = [];
  const database = getDb();

  if (sector_key && sector_key !== "all" && database) {
    const doc = await database.collection("sector_recipients").findOne({ sector_key });
    if (doc && doc.enabled === false) return { sent: 0, results: [], skipped: true };
    if (doc && emails.length === 0) {
      emails = (doc.emails || []).filter(Boolean);
      displayName = doc.display_name || sector_key;
      cc = doc.cc || [];
      bcc = doc.bcc || [];
    }
  }

  if (emails.length === 0) return { sent: 0, results: [] };

  const subject = isTest ? `ISMIGS – Test notification for ${displayName}` : `ISMIGS – Update for ${displayName}`;
  let text, html;
  if (isTest) {
    if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY required for test emails.");
    let linkedin_post_text, hashtags, commodity, production, consumption, import_dependency, risk_score, projected_deficit_year, sector_impact;
    const sectorType = getSectorType(sector_key);
    if (sectorType === "energy") {
      try {
        const postData = await generateLinkedInPost(displayName);
        linkedin_post_text = postData.linkedin_post_text;
        hashtags = postData.hashtags;
        commodity = postData.commodity;
        production = postData.production;
        consumption = postData.consumption;
        import_dependency = postData.import_dependency;
        risk_score = postData.risk_score;
        projected_deficit_year = postData.projected_deficit_year;
        sector_impact = postData.sector_impact;
      } catch (e) {
        const fallback = await generateSectorSamplePost(sector_key, displayName);
        linkedin_post_text = fallback.linkedin_post_text;
        hashtags = fallback.hashtags;
        commodity = displayName;
      }
    } else {
      const fallback = await generateSectorSamplePost(sector_key, displayName);
      linkedin_post_text = fallback.linkedin_post_text;
      hashtags = fallback.hashtags;
      commodity = displayName;
    }
    const token = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 48 * 60 * 60 * 1000);
    const decision = {
      token,
      commodity: commodity || displayName,
      linkedin_post_text,
      hashtags: Array.isArray(hashtags) ? hashtags : [hashtags].filter(Boolean),
      status: "pending",
      created_at: now,
      expires_at: expiresAt,
      responded_at: null,
      production: production ?? null,
      consumption: consumption ?? null,
      import_dependency: import_dependency ?? null,
      risk_score: risk_score ?? null,
      projected_deficit_year: projected_deficit_year ?? null,
      sector_impact: sector_impact ?? null,
    };
    if (database) {
      await database.collection("admin_decisions").insertOne(decision);
    }
    const { textSuffix, htmlSuffix } = appendConfirmationBlock(linkedin_post_text, hashtags, token);
    text = linkedin_post_text + textSuffix;
    html = `<p style="white-space:pre-wrap;">${linkedin_post_text.replace(/\n/g, "<br>")}</p>` + htmlSuffix;
  } else {
    text = `Update for sector: ${displayName}.`;
    html = text.replace(/\n/g, "<br>");
  }

  const results = [];
  for (const to of emails) {
    try {
      await transport.sendMail({
        from: fromAddr,
        to,
        cc: cc.length ? cc : undefined,
        bcc: bcc.length ? bcc : undefined,
        subject,
        text,
        html,
      });
      results.push({ to, ok: true });
      await insertEmailLog(sector_key, to, subject, true, null);
    } catch (err) {
      results.push({ to, ok: false, error: err.message });
      await insertEmailLog(sector_key, to, subject, false, err.message);
    }
  }
  return { sent: results.filter((r) => r.ok).length, results };
}

app.post("/api/send-sector-email", async (req, res) => {
  const { sector_key, emails: bodyEmails, isTest = true, insights, warnings } = req.body || {};
  const settings = await getSettings();
  if (settings.notifications_enabled === false) {
    return res.status(503).json({ error: "Notifications are disabled in admin settings." });
  }
  const database = getDb();

  const hasDigestInput =
    (Array.isArray(insights) && insights.some((s) => String(s).trim())) ||
    (Array.isArray(warnings) && warnings.some((s) => String(s).trim()));
  if (hasDigestInput && !OPENAI_API_KEY) {
    return res.status(503).json({ error: "OPENAI_API_KEY required for digest emails." });
  }

  if (sector_key === "all") {
    if (!database) return res.status(503).json({ error: "MongoDB not configured." });
    const rows = await database.collection("sector_recipients").find({ enabled: true }).toArray();
    const sectors = rows.filter((r) => (r.emails || []).length > 0);
    let transport, fromAddr;
    if (smtpHost && smtpUser && smtpPass) {
      fromAddr = getFrom(settings);
      transport = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass },
      });
    } else {
      const ethereal = await createEtherealTransport();
      transport = ethereal.transport;
      fromAddr = ethereal.fromAddr;
    }
    if (hasDigestInput) {
      try {
        const digestText = await generateLinkedInDigest(insights, warnings);
        const digestSubject = "ISMIGS – Top insights & critical warnings";
        const digestHtml = digestText.replace(/\n/g, "<br>");
        const results = [];
        let totalSent = 0, totalFailed = 0;
        for (const row of sectors) {
          let sent = 0, failed = 0;
          for (const to of row.emails || []) {
            try {
              await transport.sendMail({
                from: fromAddr,
                to,
                subject: digestSubject,
                text: digestText,
                html: digestHtml,
              });
              sent++;
              totalSent++;
              await insertEmailLog(row.sector_key, to, digestSubject, true, null);
            } catch (err) {
              failed++;
              totalFailed++;
              await insertEmailLog(row.sector_key, to, digestSubject, false, err.message);
            }
          }
          results.push({ sector_key: row.sector_key, sent, failed });
        }
        return res.json({ sent: totalSent, failed: totalFailed, results, dev: !(smtpHost && smtpUser && smtpPass) });
      } catch (e) {
        return res.status(500).json({ error: e.message });
      }
    }
    if (!OPENAI_API_KEY) {
      return res.status(503).json({ error: "OPENAI_API_KEY required for test emails." });
    }
    const results = [];
    let totalSent = 0, totalFailed = 0;
    try {
      for (const row of sectors) {
        const out = await sendOneSector(row.sector_key, row.emails, true, settings, transport, fromAddr);
        const failed = (out.results || []).filter((r) => !r.ok).length;
        totalSent += out.sent;
        totalFailed += failed;
        results.push({ sector_key: row.sector_key, sent: out.sent, failed });
      }
    } catch (e) {
      return res.status(500).json({ error: e.message || "Test email send failed." });
    }
    return res.json({
      sent: totalSent,
      failed: totalFailed,
      results,
      dev: !(smtpHost && smtpUser && smtpPass),
    });
  }

  let emails = Array.isArray(bodyEmails) ? bodyEmails.filter((e) => String(e).trim()) : [];
  let displayName = sector_key || "Sector";
  let cc = [], bcc = [];

  if (sector_key && emails.length === 0 && database) {
    const data = await database.collection("sector_recipients").findOne({ sector_key });
    if (data && data.enabled === false) {
      return res.status(400).json({ error: "This sector is disabled." });
    }
    if (data) {
      emails = (data.emails || []).filter(Boolean);
      displayName = data.display_name || sector_key;
      cc = data.cc || [];
      bcc = data.bcc || [];
    }
  }

  if (emails.length === 0) {
    return res.status(400).json({ error: "No email addresses to send to." });
  }

  let subject, text, html;
  if (hasDigestInput) {
    try {
      text = await generateLinkedInDigest(insights, warnings);
      subject = "ISMIGS – Top insights & critical warnings";
      html = text.replace(/\n/g, "<br>");
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  } else {
    subject = isTest ? `ISMIGS – Test notification for ${displayName}` : `ISMIGS – Update for ${displayName}`;
    if (isTest) {
      if (!OPENAI_API_KEY) {
        return res.status(503).json({ error: "OPENAI_API_KEY required for test emails." });
      }
      try {
        let linkedin_post_text, hashtags, commodity, production, consumption, import_dependency, risk_score, projected_deficit_year, sector_impact;
        const sectorType = getSectorType(sector_key);
        if (sectorType === "energy") {
          try {
            const postData = await generateLinkedInPost(displayName);
            linkedin_post_text = postData.linkedin_post_text;
            hashtags = postData.hashtags;
            commodity = postData.commodity;
            production = postData.production;
            consumption = postData.consumption;
            import_dependency = postData.import_dependency;
            risk_score = postData.risk_score;
            projected_deficit_year = postData.projected_deficit_year;
            sector_impact = postData.sector_impact;
          } catch (e) {
            const fallback = await generateSectorSamplePost(sector_key, displayName);
            linkedin_post_text = fallback.linkedin_post_text;
            hashtags = fallback.hashtags;
            commodity = displayName;
          }
        } else {
          const fallback = await generateSectorSamplePost(sector_key, displayName);
          linkedin_post_text = fallback.linkedin_post_text;
          hashtags = fallback.hashtags;
          commodity = displayName;
        }
        const token = crypto.randomUUID();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 48 * 60 * 60 * 1000);
        const decision = {
          token,
          commodity: commodity || displayName,
          linkedin_post_text,
          hashtags: Array.isArray(hashtags) ? hashtags : [hashtags].filter(Boolean),
          status: "pending",
          created_at: now,
          expires_at: expiresAt,
          responded_at: null,
          production: production ?? null,
          consumption: consumption ?? null,
          import_dependency: import_dependency ?? null,
          risk_score: risk_score ?? null,
          projected_deficit_year: projected_deficit_year ?? null,
          sector_impact: sector_impact ?? null,
        };
        if (database) {
          await database.collection("admin_decisions").insertOne(decision);
        }
        const { textSuffix, htmlSuffix } = appendConfirmationBlock(linkedin_post_text, hashtags, token);
        text = linkedin_post_text + textSuffix;
        html = `<p style="white-space:pre-wrap;">${linkedin_post_text.replace(/\n/g, "<br>")}</p>` + htmlSuffix;
      } catch (e) {
        return res.status(500).json({ error: e.message || "Sector LinkedIn post generation failed." });
      }
    } else {
      text = `Update for sector: ${displayName}.`;
      html = text.replace(/\n/g, "<br>");
    }
  }

  let transport, fromAddr;
  if (smtpHost && smtpUser && smtpPass) {
    fromAddr = getFrom(settings);
    transport = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    });
  } else {
    const ethereal = await createEtherealTransport();
    transport = ethereal.transport;
    fromAddr = ethereal.fromAddr;
  }

  try {
    const results = [];
    for (const to of emails) {
      try {
        await transport.sendMail({
          from: fromAddr,
          to,
          cc: cc.length ? cc : undefined,
          bcc: bcc.length ? bcc : undefined,
          subject,
          text,
          html,
        });
        results.push({ to, ok: true });
        await insertEmailLog(sector_key, to, subject, true, null);
      } catch (err) {
        results.push({ to, ok: false, error: err.message });
        await insertEmailLog(sector_key, to, subject, false, err.message);
      }
    }
    res.json({
      sent: results.filter((r) => r.ok).length,
      results,
      dev: !(smtpHost && smtpUser && smtpPass),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Energy disclosure: decision + send disclosure ----------

app.get("/api/admin/decision", async (req, res) => {
  const { token, type } = req.query || {};
  const database = getDb();
  if (!token || typeof token !== "string") {
    return res.redirect(getDecisionRedirectUrl("expired"));
  }
  if (!database) {
    return res.redirect(getDecisionRedirectUrl("expired"));
  }
  const doc = await database.collection("admin_decisions").findOne({ token });
  if (!doc) {
    console.warn("Admin decision: token not found", token);
    return res.redirect(getDecisionRedirectUrl("expired"));
  }
  const now = new Date();
  if (new Date(doc.expires_at) < now) {
    return res.redirect(getDecisionRedirectUrl("expired"));
  }
  if (doc.status !== "pending") {
    return res.redirect(getDecisionRedirectUrl(doc.status === "approved" ? "approved" : "rejected"));
  }
  const action = type === "approve" ? "approved" : type === "reject" ? "rejected" : null;
  if (!action) {
    return res.redirect(getDecisionRedirectUrl("expired"));
  }
  await database.collection("admin_decisions").updateOne(
    { token },
    { $set: { status: action === "approved" ? "approved" : "rejected", responded_at: now } }
  );
  if (action === "approved") {
    try {
      const updated = await database.collection("admin_decisions").findOne({ token });
      await triggerN8nWebhook(updated || doc);
    } catch (err) {
      console.error("n8n webhook error after approval:", err.message);
    }
  }
  return res.redirect(getDecisionRedirectUrl(action === "approved" ? "approved" : "rejected"));
});

app.get("/api/energy-commodities", async (_req, res) => {
  try {
    const list = await listCommodities();
    res.json(list);
  } catch (e) {
    res.status(502).json({ error: e.message || "Failed to fetch commodities." });
  }
});

app.post("/api/send-energy-disclosure", async (req, res) => {
  const { commodity, adminEmail } = req.body || {};
  const email = typeof adminEmail === "string" ? adminEmail.trim() : "";
  const commodityName = typeof commodity === "string" ? commodity.trim() : null;
  if (!email) {
    return res.status(400).json({ error: "adminEmail is required." });
  }
  const settings = await getSettings();
  if (settings.notifications_enabled === false) {
    return res.status(503).json({ error: "Notifications are disabled in admin settings." });
  }
  let transport, fromAddr;
  if (smtpHost && smtpUser && smtpPass) {
    fromAddr = getFrom(settings);
    transport = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    });
  } else {
    try {
      const ethereal = await createEtherealTransportWithTimeout();
      transport = ethereal.transport;
      fromAddr = ethereal.fromAddr;
    } catch (e) {
      console.error("send-energy-disclosure ethereal:", e.message);
      return res.status(503).json({
        error: "Email transport not configured. Set SMTP_* env vars for production.",
      });
    }
  }
  let commodityList = [];
  try {
    commodityList = await listCommodities();
  } catch (e) {
    console.error("send-energy-disclosure listCommodities:", e.message);
    return res.status(502).json({ error: "Energy data temporarily unavailable." });
  }
  const commodityToUse =
    commodityName && commodityList.includes(commodityName) ? commodityName : commodityList[0] || null;
  if (!commodityToUse) {
    return res.status(400).json({ error: "No commodity specified and no energy data available." });
  }
  try {
    const postData = await generateLinkedInPost(commodityToUse);
    await sendConfirmationEmail(email, postData, transport, fromAddr);
    res.json({
      ok: true,
      message: "Confirmation email sent. Check your inbox and use Yes/No to approve or reject the LinkedIn post.",
      commodity: commodityToUse,
    });
  } catch (e) {
    const msg = e.message || "";
    const isUpstream =
      /OPENAI_API_KEY|OpenAI API|api\.openai\.com|No energy commodity|fetchWithRetry|MOSPI|Energy data/i.test(msg);
    const isEmail = /sendMail|Ethereal|createTestAccount|SMTP|timeout/i.test(msg);
    if (isUpstream) {
      console.error("send-energy-disclosure error:", e.message);
      return res.status(502).json({
        error: "LinkedIn post generation failed. Check OPENAI_API_KEY and upstream data.",
      });
    }
    if (isEmail) {
      console.error("send-energy-disclosure error:", e.message);
      return res.status(503).json({ error: "Email service temporarily unavailable." });
    }
    console.error("send-energy-disclosure error:", e.stack || e.message);
    return res.status(500).json({ error: e.message || "Failed to send energy disclosure." });
  }
});

// ---------- Cron: sector critical alerts (every 6h) ----------

const RISK_THRESHOLD = Number(process.env.ENERGY_RISK_THRESHOLD) || 40;

function slugifyCommodity(s) {
  return String(s).toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
}

async function runSectorCriticalAlerts() {
  const database = getDb();
  if (!database) {
    throw new Error("MongoDB not configured.");
  }
  let commodities;
  try {
    commodities = await listCommodities();
  } catch (e) {
    throw new Error("Failed to fetch commodities: " + e.message);
  }
  const results = [];
  const settings = await getSettings();
  let transport, fromAddr;
  if (smtpHost && smtpUser && smtpPass) {
    fromAddr = getFrom(settings);
    transport = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    });
  } else {
    try {
      const ethereal = await createEtherealTransport();
      transport = ethereal.transport;
      fromAddr = ethereal.fromAddr;
    } catch (e) {
      throw new Error("No SMTP or Ethereal available.");
    }
  }
  for (const commodityName of commodities) {
    let stats;
    try {
      stats = await fetchCommodityStats(commodityName);
    } catch (e) {
      continue;
    }
    const isCritical = stats.riskScore >= RISK_THRESHOLD || (stats.projectedDeficitYear != null);
    if (!isCritical) continue;
    const sectorKey = `energy:${slugifyCommodity(commodityName)}`;
    const row = await database.collection("sector_recipients").findOne({ sector_key: sectorKey, enabled: true });
    const recipients = row?.emails || [];
    if (recipients.length === 0) continue;
    const topSectors = stats.topSectors || [];
    const reason = stats.riskReasons?.length ? stats.riskReasons.join("; ") : "Risk or projected deficit.";
    for (const sec of topSectors) {
      const alertHtml = `<p><strong>Sector:</strong> ${sec.name}</p><p><strong>% consumption share:</strong> ${sec.sharePct.toFixed(1)}%</p><p><strong>Risk reason:</strong> ${reason}</p><p><strong>Commodity:</strong> ${commodityName}</p><p>Recommended: Monitor supply-demand and consider mitigation per ISMIGS dashboard.</p>`;
      const alertText = `Sector: ${sec.name}. % consumption share: ${sec.sharePct.toFixed(1)}%. Risk reason: ${reason}. Commodity: ${commodityName}. Recommended: Monitor supply-demand and consider mitigation per ISMIGS dashboard.`;
      try {
        const sentAt = new Date();
        for (const to of recipients) {
          await transport.sendMail({
            from: fromAddr,
            to,
            subject: `ISMIGS – Critical alert: ${commodityName} (${sec.name})`,
            text: alertText,
            html: alertHtml,
          });
        }
        await database.collection("sector_alerts_log").insertOne({
          commodity: commodityName,
          sector: sec.name,
          risk_score: stats.riskScore,
          sent_at: sentAt,
          alert_type: stats.projectedDeficitYear ? "projected_deficit" : "risk_threshold",
          recipient_count: recipients.length,
        });
        results.push({ commodity: commodityName, sector: sec.name, sent: recipients.length });
      } catch (e) {
        console.error("Alert send failed:", e.message);
      }
    }
  }
  return { results };
}

app.get("/api/cron/sector-critical-alerts", async (req, res) => {
  const secret = req.headers.authorization?.replace(/^Bearer\s+/i, "") || req.query?.secret || "";
  if (secret !== CRON_SECRET) {
    return res.status(401).json({ error: "Unauthorized." });
  }
  try {
    const { results } = await runSectorCriticalAlerts();
    res.json({ ok: true, results });
  } catch (e) {
    if (e.message === "MongoDB not configured.") return res.status(503).json({ error: e.message });
    if (e.message.startsWith("Failed to fetch commodities")) return res.status(502).json({ error: e.message });
    if (e.message === "No SMTP or Ethereal available.") return res.status(503).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ---------- Sector alerts log (admin) ----------

app.get("/api/sector-alerts-log", async (req, res) => {
  const database = getDb();
  if (!database) {
    return res.status(503).json({ error: "MongoDB not configured." });
  }
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const offset = parseInt(req.query.offset, 10) || 0;
  const commodity = typeof req.query.commodity === "string" ? req.query.commodity.trim() : null;
  const since = typeof req.query.since === "string" ? req.query.since.trim() : null;
  const filter = {};
  if (commodity) filter.commodity = commodity;
  if (since) {
    const sinceDate = new Date(since);
    if (!isNaN(sinceDate.getTime())) filter.sent_at = { $gte: sinceDate };
  }
  try {
    const col = database.collection("sector_alerts_log");
    const [items, total] = await Promise.all([
      col.find(filter).sort({ sent_at: -1 }).skip(offset).limit(limit).toArray(),
      col.countDocuments(filter),
    ]);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const summaryCursor = col.find({ sent_at: { $gte: sevenDaysAgo } });
    const summaryItems = await summaryCursor.toArray();
    let totalLast7Days = summaryItems.length;
    const byCommodity = {};
    for (const row of summaryItems) {
      const c = row.commodity || "Unknown";
      byCommodity[c] = (byCommodity[c] || 0) + 1;
    }
    let mappedItems = items.map((doc) => ({
      id: doc._id.toString(),
      commodity: doc.commodity,
      sector: doc.sector,
      risk_score: doc.risk_score,
      sent_at: doc.sent_at ? new Date(doc.sent_at).toISOString() : null,
      alert_type: doc.alert_type,
      recipient_count: doc.recipient_count ?? 0,
    }));
    if (mappedItems.length === 0 && !commodity && !since) {
      let commodities = [];
      try {
        commodities = await listCommodities();
      } catch (_) {}
      if (commodities.length === 0) commodities = ["Coal", "Natural gas", "Crude oil", "Electricity"];
      const sectors = ["Industry", "Transport", "Residential"];
      const now = Date.now();
      const sampleItems = [];
      for (let i = 0; i < Math.min(5, commodities.length * 2); i++) {
        const comm = commodities[i % commodities.length];
        const sector = sectors[i % sectors.length];
        const sentAt = new Date(now - (i + 1) * 24 * 60 * 60 * 1000);
        sampleItems.push({
          id: `sample-${i + 1}`,
          commodity: comm,
          sector,
          risk_score: 40 + (i * 7) % 45,
          sent_at: sentAt.toISOString(),
          alert_type: i % 2 === 0 ? "risk_threshold" : "projected_deficit",
          recipient_count: (i % 2) + 1,
        });
        if (sentAt >= sevenDaysAgo) {
          totalLast7Days += 1;
          byCommodity[comm] = (byCommodity[comm] || 0) + 1;
        }
      }
      sampleItems.sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at));
      mappedItems = sampleItems;
    }
    res.json({
      items: mappedItems,
      total: total > 0 ? total : mappedItems.length,
      summary: { totalLast7Days, byCommodity },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/run-sector-alerts", requireAuth, async (req, res) => {
  try {
    const { results } = await runSectorCriticalAlerts();
    res.json({ ok: true, results });
  } catch (e) {
    if (e.message === "MongoDB not configured.") return res.status(503).json({ error: e.message });
    if (e.message.startsWith("Failed to fetch commodities")) {
      const msg = /fetch failed|ECONNREFUSED|ETIMEDOUT|aborted|network/i.test(e.message)
        ? "Commodity data source is temporarily unreachable. Please try again in a moment."
        : e.message;
      return res.status(502).json({ error: msg });
    }
    res.status(500).json({ error: e.message || "Run sector alerts failed." });
  }
});

app.get("/api/admin/decisions", requireAuth, async (req, res) => {
  const database = getDb();
  if (!database) {
    return res.status(503).json({ error: "MongoDB not configured." });
  }
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  try {
    const items = await database
      .collection("admin_decisions")
      .find({})
      .sort({ created_at: -1 })
      .limit(limit)
      .toArray();
    res.json({
      items: items.map((doc) => ({
        id: doc._id.toString(),
        commodity: doc.commodity ?? null,
        status: doc.status ?? "pending",
        created_at: doc.created_at ? new Date(doc.created_at).toISOString() : null,
        responded_at: doc.responded_at ? new Date(doc.responded_at).toISOString() : null,
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/send-email", async (req, res) => {
  const { to, subject, text, html } = req.body || {};
  if (!Array.isArray(to) || to.length === 0 || !subject) {
    return res.status(400).json({ error: "Body must include to (string[]) and subject." });
  }
  try {
    let transport, fromAddr;
    if (smtpHost && smtpUser && smtpPass) {
      const settings = await getSettings();
      fromAddr = getFrom(settings);
      transport = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass },
      });
    } else {
      const ethereal = await createEtherealTransport();
      transport = ethereal.transport;
      fromAddr = ethereal.fromAddr;
    }
    const results = [];
    for (const recipient of to) {
      try {
        await transport.sendMail({
          from: fromAddr,
          to: recipient,
          subject,
          text: text || "",
          html: html || (text ? text.replace(/\n/g, "<br>") : ""),
        });
        results.push({ to: recipient, ok: true });
      } catch (err) {
        results.push({ to: recipient, ok: false, error: err.message });
      }
    }
    res.json({
      sent: results.filter((r) => r.ok).length,
      results,
      dev: !(smtpHost && smtpUser && smtpPass),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const port = process.env.PORT || 3001;

connectDb()
  .then(() => {
    app.listen(port, () => {
      const mongo = db ? "MongoDB ok" : "MongoDB not connected";
      const smtp = smtpHost && smtpUser && smtpPass ? "SMTP ok" : "SMTP not set (optional)";
      console.log(`ISMIGS backend listening on port ${port} | ${mongo} | ${smtp}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    app.listen(port, () => {
      const smtp = smtpHost && smtpUser && smtpPass ? "SMTP ok" : "SMTP not set (optional)";
      console.log(`ISMIGS backend listening on port ${port} (no DB) | ${smtp}`);
    });
  });
