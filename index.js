/**
 * ISMIGS Node.js backend: MongoDB (sector recipients, email logs, settings), JWT auth.
 * All email is sent via Nodemailer (SMTP when configured, or Ethereal in dev).
 * Run from backend folder: npm run dev
 */
import "dotenv/config";
import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const JWT_SECRET = "ismigs-dev-secret-change-in-production";
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "admin123";
const MONGODB_URI = "mongodb+srv://myselfyourstej_db_user:ismigs@cluster0.eq96ml6.mongodb.net/?appName=Cluster0";

let db = null;
const DB_NAME = "ismigs";

async function connectDb() {
  const uri = process.env.MONGODB_URI || MONGODB_URI;
  const client = await MongoClient.connect(uri);
  db = client.db(DB_NAME);
  await db.collection("admin_settings").createIndex({ key: 1 }, { unique: true }).catch(() => {});
  await db.collection("sector_recipients").createIndex({ sector_key: 1 }, { unique: true }).catch(() => {});
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

// ---------- Auth (no requireAuth) ----------

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { sub: "admin", iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    return res.json({ token });
  }
  return res.status(401).json({ error: "Invalid username or password." });
});

app.use("/api", requireAuth);

app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.user || "admin" });
});

// ---------- Sector recipients ----------

app.get("/api/sector-recipients", async (req, res) => {
  const database = getDb();
  if (!database) return res.status(503).json({ error: "MongoDB not configured." });
  try {
    const rows = await database.collection("sector_recipients").find({}).toArray();
    const map = {};
    rows.forEach((row) => {
      map[row.sector_key] = {
        sector_key: row.sector_key,
        display_name: row.display_name || row.sector_key,
        emails: row.emails || [],
        updated_at: row.updated_at ? new Date(row.updated_at).toISOString() : new Date().toISOString(),
        label: row.label ?? null,
        enabled: row.enabled !== false,
        cc: row.cc || [],
        bcc: row.bcc || [],
      };
    });
    res.json(map);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
  const text = isTest ? `This is a test email from ISMIGS. You are receiving this because you are subscribed to sector: ${displayName}.` : `Update for sector: ${displayName}.`;
  const html = text.replace(/\n/g, "<br>");

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
    const results = [];
    let totalSent = 0, totalFailed = 0;
    for (const row of sectors) {
      const out = await sendOneSector(row.sector_key, row.emails, true, settings, transport, fromAddr);
      const failed = (out.results || []).filter((r) => !r.ok).length;
      totalSent += out.sent;
      totalFailed += failed;
      results.push({ sector_key: row.sector_key, sent: out.sent, failed });
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
    text = isTest ? `This is a test email from ISMIGS. You are receiving this because you are subscribed to sector: ${displayName}.` : `Update for sector: ${displayName}.`;
    html = text.replace(/\n/g, "<br>");
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
