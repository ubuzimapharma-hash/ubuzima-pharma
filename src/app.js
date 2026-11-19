import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import bcrypt from "bcryptjs";
import connectPgSimple from "connect-pg-simple";
import cors from "cors";
import express from "express";
import { rateLimit } from "express-rate-limit";
import session from "express-session";
import helmet from "helmet";
import multer from "multer";
import sharp from "sharp";
import { config } from "./config.js";
import { sanitizeArticleHtml } from "./content.js";
import { pool } from "./db.js";
import { emailIsConfigured, sendEmailBatch } from "./email.js";
import {
  validateNewsArticle,
  validateOrderItems,
  validatePatientRegistration,
  validateProfileDetails,
  validateProduct,
  validateStaffInvitation,
  validateVideo
} from "./validation.js";

const PgSession = connectPgSimple(session);
const SESSION_COOKIE = "ubuzima.sid";
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(randomBytes(32).toString("hex"), 12);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 20, parts: 21 }
});
const videoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxVideoUploadBytes, files: 1, fields: 2, parts: 3 }
});
const prescriptionUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 4, parts: 5 }
});
const salesUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 2, parts: 3 }
});

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function csrfMatches(expected, received) {
  if (typeof expected !== "string" || typeof received !== "string") return false;
  const expectedBuffer = Buffer.from(expected);
  const receivedBuffer = Buffer.from(received);
  return expectedBuffer.length === receivedBuffer.length && timingSafeEqual(expectedBuffer, receivedBuffer);
}

function isDevelopmentOrigin(origin) {
  if (config.isProduction || typeof origin !== "string") return false;
  try {
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === "http:" &&
      ["localhost", "127.0.0.1"].includes(parsedOrigin.hostname);
  } catch {
    return false;
  }
}

function publicProduct(row) {
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    generic_name: row.generic_name,
    active_ingredient: row.active_ingredient,
    strength: row.strength,
    dosage_form: row.dosage_form,
    pack_size: row.pack_size,
    manufacturer: row.manufacturer,
    directions_for_use: row.directions_for_use,
    indications: row.indications,
    warnings: row.warnings,
    storage_instructions: row.storage_instructions,
    price_bif: row.price_bif === null ? null : Number(row.price_bif),
    stock_quantity: row.stock_quantity,
    image_url: row.image_url,
    is_available: row.is_available,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function doctorCallUrl(consultationId) {
  const callUrl = new URL("/consultation.html", config.publicSiteUrl);
  callUrl.searchParams.set("consultation_id", consultationId);
  return callUrl.href;
}

function validateCallSignal(input) {
  const signal = input?.signal;
  if (!signal || typeof signal !== "object" || Array.isArray(signal) ||
      !["offer", "answer", "candidate", "hangup"].includes(signal.type)) {
    return { error: "Call signal is invalid." };
  }
  let serialized;
  try { serialized = JSON.stringify(signal); } catch { return { error: "Call signal is invalid." }; }
  if (Buffer.byteLength(serialized, "utf8") > 16_000) return { error: "Call signal is too large." };
  return { value: signal };
}

function callSignalCursor(req, res) {
  const raw = typeof req.query.after === "string" ? req.query.after : "0";
  if (!/^\d{1,15}$/.test(raw)) {
    res.status(400).json({ error: "Signal cursor is invalid." });
    return null;
  }
  return raw;
}

async function writeImage(buffer) {
  const processor = sharp(buffer, { limitInputPixels: 20_000_000 });
  let metadata;
  try {
    metadata = await processor.metadata();
  } catch (error) {
    if (/Input buffer|unsupported image|Vips|corrupt|Invalid image/i.test(error.message)) error.status = 400;
    throw error;
  }
  if (!["jpeg", "png", "webp"].includes(metadata.format)) {
    throw Object.assign(new Error("Image must be a valid JPEG, PNG, or WebP file."), { status: 400 });
  }
  const filename = `${randomUUID()}.webp`;
  const outputPath = path.join(config.uploadDirectory, filename);
  try {
    await processor
      .rotate()
      .resize({ width: 1200, height: 1200, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 82 })
      .toFile(outputPath);
  } catch (error) {
    if (/Input buffer|unsupported image|Vips|corrupt|pixel limit|Invalid image/i.test(error.message)) error.status = 400;
    throw error;
  }
  return { filename, url: `/uploads/${filename}` };
}

async function writeVideo(file) {
  const extension = file.mimetype === "video/mp4" ? "mp4" : file.mimetype === "video/webm" ? "webm" : "";
  const isMp4 = extension === "mp4" && file.buffer.subarray(4, 8).toString() === "ftyp";
  const isWebm = extension === "webm" && file.buffer.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]));
  if (!isMp4 && !isWebm) {
    throw Object.assign(new Error("Video must be a valid MP4 or WebM file."), { status: 400 });
  }
  await fs.mkdir(config.videoUploadDirectory, { recursive: true });
  const filename = `${randomUUID()}.${extension}`;
  await fs.writeFile(path.join(config.videoUploadDirectory, filename), file.buffer, { flag: "wx" });
  return `/uploads/videos/${filename}`;
}

async function storePrescription(file) {
  if (!file) return null;
  const buffer = file.buffer;
  let extension;
  let mimeType;
  if (buffer.subarray(0, 5).toString() === "%PDF-") {
    extension = "pdf";
    mimeType = "application/pdf";
  } else if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    extension = "jpg";
    mimeType = "image/jpeg";
  } else if (buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    extension = "png";
    mimeType = "image/png";
  } else if (buffer.subarray(0, 4).toString() === "RIFF" && buffer.subarray(8, 12).toString() === "WEBP") {
    extension = "webp";
    mimeType = "image/webp";
  } else {
    throw Object.assign(new Error("Prescription must be a PDF, JPEG, PNG, or WebP file."), { status: 400 });
  }
  await fs.mkdir(config.patientCareDirectory, { recursive: true });
  const filename = `${randomUUID()}.${extension}`;
  await fs.writeFile(path.join(config.patientCareDirectory, filename), buffer, { flag: "wx", mode: 0o600 });
  return { filename, mimeType };
}

async function storeSalesImage(file) {
  if (!file) throw Object.assign(new Error("Upload a photo of the items sold."), { status: 400 });
  const buffer = file.buffer;
  const isJpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  const isPng = buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  const isWebp = buffer.subarray(0, 4).toString() === "RIFF" && buffer.subarray(8, 12).toString() === "WEBP";
  if (!isJpeg && !isPng && !isWebp) throw Object.assign(new Error("Photo must be a valid JPEG, PNG, or WebP file."), { status: 400 });
  await fs.mkdir(config.salesDirectory, { recursive: true });
  const filename = `${randomUUID()}.webp`;
  try {
    await sharp(buffer, { limitInputPixels: 20_000_000 })
      .rotate().resize({ width: 1600, height: 1600, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 82 }).toFile(path.join(config.salesDirectory, filename));
  } catch (error) {
    if (/Input buffer|unsupported image|Vips|corrupt|pixel limit|Invalid image/i.test(error.message)) {
      throw Object.assign(new Error("Photo must be a valid JPEG, PNG, or WebP file."), { status: 400 });
    }
    throw error;
  }
  return filename;
}

async function deletePrescription(filename) {
  if (!filename || path.basename(filename) !== filename) return;
  await fs.unlink(path.join(config.patientCareDirectory, filename)).catch(error => {
    if (error.code !== "ENOENT") throw error;
  });
}

function validateCareMessage(message) {
  const value = typeof message === "string" ? message.trim() : "";
  if (!value || value.length > 4000) return { error: "Message is required and must be at most 4,000 characters." };
  return { value };
}

async function removeVideo(videoUrl) {
  const filename = path.basename(videoUrl);
  if (!/^([0-9a-f-]+)\.(mp4|webm)$/.test(filename)) return;
  await fs.unlink(path.join(config.videoUploadDirectory, filename)).catch(error => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function publishScheduledContent() {
  const dueArticles = await pool.query(
    `UPDATE news_articles SET status = 'published', published_at = NOW(), updated_at = NOW()
     WHERE status = 'scheduled' AND scheduled_at <= NOW()
     RETURNING id, title, summary, video_url`
  );
  for (const article of dueArticles.rows) await deliverNewsArticle(article);
  await pool.query(
    `UPDATE videos SET status = 'published', published_at = NOW(), updated_at = NOW()
     WHERE status = 'scheduled' AND scheduled_at <= NOW()`
  );
}

function requireStaff(req, res, next) {
  if (!req.session.staffId) return res.status(401).json({ error: "Staff sign-in required." });
  pool.query(
    "SELECT id, username, role, full_name, phone, profile_image_url FROM staff_users WHERE id = $1 AND is_active = TRUE",
    [req.session.staffId]
  ).then(result => {
    if (!result.rowCount) return res.status(401).json({ error: "Staff sign-in required." });
    req.staffUser = result.rows[0];
    return next();
  }).catch(next);
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.staffUser?.role !== role) return res.status(403).json({ error: "This account does not have permission to perform this action." });
    return next();
  };
}

function requireAnyRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.staffUser?.role)) return res.status(403).json({ error: "This account does not have permission to perform this action." });
    return next();
  };
}

function requirePatient(req, res, next) {
  if (!req.session.patientId) return res.status(401).json({ error: "Patient sign-in required." });
  pool.query(
    "SELECT id, email, full_name, phone, profile_image_url FROM patient_users WHERE id = $1 AND is_active = TRUE",
    [req.session.patientId]
  ).then(result => {
    if (!result.rowCount) return res.status(401).json({ error: "Patient sign-in required." });
    req.patientUser = result.rows[0];
    return next();
  }).catch(next);
}

function requireCsrf(req, res, next) {
  if (!csrfMatches(req.session.csrfToken, req.get("X-CSRF-Token"))) {
    return res.status(403).json({ error: "Request verification failed. Refresh the page and try again." });
  }
  return next();
}

function requireCsrfForMutation(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  return requireCsrf(req, res, next);
}

function recordAudit(client, staffId, action, productId, details = {}) {
  return client.query(
    "INSERT INTO audit_logs (staff_user_id, action, product_id, details) VALUES ($1, $2, $3, $4)",
    [staffId, action, productId, details]
  );
}

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function escapeEmailHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function formatEmailBody(value) {
  return escapeEmailHtml(value).replace(/\r?\n/g, "<br>");
}
function newsletterTopicSections(article) {
  const plain = String(article.body || "").replace(/<br\s*\/?\s*>/gi, " ").replace(/<\/li>/gi, " ").replace(/<[^>]*>/g, " ").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/\s+/g, " ").trim();
  const headings = [
    { title: "Paracetamol ikora gute?", match: "Paracetamol ikora gute?" },
    { title: "Ni izihe ngaruka?", match: "Ni izihe ngaruka zo gukoresha paracetamol nabi?" },
    { title: "Ni gute kuyikoresha neza?", match: "Ni gute umuntu yokoresha paracetamol neza?" }
  ];
  const positions = headings.map(item => plain.toLowerCase().indexOf(item.match.toLowerCase()));
  if (/paracetamol/i.test(article.title || "") && positions.every(position => position >= 0)) {
    return [
      { title: headings[0].title, text: plain.slice(0, positions[1]) },
      { title: headings[1].title, text: plain.slice(positions[1], positions[2]) },
      { title: headings[2].title, text: plain.slice(positions[2]) }
    ];
  }
  const words = plain.split(/\s+/).filter(Boolean);
  const size = Math.max(1, Math.ceil(words.length / 3));
  return ["Incamake y'inkuru", "Ivy'ingenzi", "Impanuro ku buzima"].map((title, index) => ({ title, text: words.slice(index * size, (index + 1) * size).join(" ") || article.summary }));
}

function newsletterEmailHtml(article, articleUrl, unsubscribeUrl) {
  const sections = newsletterTopicSections(article);
  const wordCount = String(article.body || "").replace(/<[^>]*>/g, " ").trim().split(/\s+/).filter(Boolean).length;
  const readMinutes = Math.max(1, Math.ceil(wordCount / 200));
  const date = article.published_at ? new Date(article.published_at).toLocaleDateString("en-US") : "";
  const title = escapeEmailHtml(article.title);
  const category = escapeEmailHtml(article.category || "Ubuzima");
  const summary = escapeEmailHtml(article.summary);
  const imageUrl = /paracetamol/i.test(article.title || "") ? `${config.publicSiteUrl}/assets/paracetamol-hero.svg` : "";
  const cards = sections.map((section, index) => {
    const panel = index === 1 ? "#e2f5e3" : "#e3efff";
    const icon = ["✓", "!", "✓"][index];
    return `<td width="33.33%" valign="top" style="padding:5px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #d5e3f2;border-radius:10px;background:#fff"><tr><td style="padding:10px;background:${panel};color:#0b2056;font:bold 14px Arial,sans-serif"><span style="margin-right:6px;color:#07943c;font-size:18px">${icon}</span>${escapeEmailHtml(section.title)}</td></tr><tr><td style="padding:10px 11px;color:#142550;font:13px/1.55 Arial,sans-serif">${escapeEmailHtml(section.text.slice(0, 190))}...</td></tr><tr><td style="padding:0 11px 12px"><a href="${escapeEmailHtml(articleUrl)}" style="color:#0645a4;font:bold 12px Arial,sans-serif">Soma vyinshi →</a></td></tr></table></td>`;
  }).join("");
  const hero = `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#e8f1ff;border-radius:12px"><tr><td width="52%" valign="middle" style="padding:20px 18px;color:#0b2056"><span style="display:inline-block;padding:7px 13px;border-radius:18px;background:#064180;color:#fff;font:bold 12px Arial,sans-serif">✚ &nbsp;${category}</span><p style="margin:12px 0 0;color:#0a2458;font:12px Arial,sans-serif">▦ &nbsp;${date} &nbsp; | &nbsp; ◷ &nbsp;${readMinutes} min isomwa</p><h1 style="margin:13px 0 0;color:#0b2056;font:bold 25px/1.2 Arial,sans-serif">${title}</h1></td>${imageUrl ? `<td width="48%" valign="middle"><img src="${escapeEmailHtml(imageUrl)}" alt="Paracetamol 500 mg" width="100%" style="display:block;width:100%;height:auto;border-radius:0 12px 12px 0"></td>` : ""}</tr></table>`;
  return `<div style="margin:0;padding:24px 8px;background:#f2f7fc"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" align="center" style="max-width:720px;margin:auto;background:#fff;border:1px solid #dce8ee;border-radius:14px;font-family:Arial,sans-serif;color:#142b4e"><tr><td style="padding:15px 20px;background:#07346e;border-radius:14px 14px 0 0;color:#fff"><span style="font-size:20px;font-weight:bold">UBUZIMA <span style="color:#52cc77">PHARMA</span></span><br><span style="font-size:11px;color:#dceaff">Ubuzima bwiza, ubuzima bw'ingenezi</span></td></tr><tr><td style="padding:16px 16px 0">${hero}</td></tr><tr><td style="padding:14px 18px 4px;color:#12244f;font:15px/1.6 Arial,sans-serif">${summary}</td></tr><tr><td style="padding:8px 18px 12px"><a href="${escapeEmailHtml(articleUrl)}" style="display:inline-block;padding:11px 20px;border-radius:24px;background:#07943c;color:#fff;text-decoration:none;font:bold 14px Arial,sans-serif">▤ &nbsp; Soma vyose &nbsp; →</a></td></tr><tr><td style="padding:0 13px 15px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>${cards}</tr></table></td></tr><tr><td style="padding:13px 18px;background:#e3efff;color:#0b2056;font:12px/1.6 Arial,sans-serif"><b>Amakuru yizewe, impanuro z'abaganga n'abafarumasiye.</b><br>UBUZIMA PHARMA · Kinama, Gitega · <a href="${escapeEmailHtml(config.publicSiteUrl)}" style="color:#0645a4">ubuzimapharma.com</a></td></tr><tr><td style="padding:13px 18px;border-top:1px solid #e5edf2;color:#718197;font:11px/1.6 Arial,sans-serif">Wakiriye iyi email kuko wiyandikishije ku makuru ya UBUZIMA PHARMA.<br><a href="${escapeEmailHtml(unsubscribeUrl)}" style="color:#0645a4">Hagarika kwakira aya makuru</a></td></tr></table></div>`;
}

function emailConfigurationError() {
  return Object.assign(
    new Error("Email is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and MAIL_FROM, or configure Resend."),
    { status: 503 }
  );
}

const newsletterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many subscription attempts. Try again later." }
});

const outboundEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many email actions. Try again later." }
});

const passwordResetRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many password recovery requests. Try again later." }
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many password reset attempts. Try again later." }
});

async function deliverNewsArticle(article) {
  const subscribers = await pool.query(
    `SELECT subscriptions.id, subscriptions.email
     FROM newsletter_subscriptions subscriptions
     WHERE subscriptions.is_verified = TRUE AND subscriptions.is_subscribed = TRUE
       AND NOT EXISTS (
         SELECT 1 FROM news_email_deliveries deliveries
         WHERE deliveries.article_id = $1 AND deliveries.subscription_id = subscriptions.id
           AND deliveries.status = 'sent'
       )
     ORDER BY subscriptions.created_at`,
    [article.id]
  );
  if (!subscribers.rowCount) return { status: "sent", sent: 0, failed: 0 };
  if (!emailIsConfigured()) return { status: "not_configured", sent: 0, failed: 0, pending: subscribers.rowCount };

  let sent = 0;
  let failed = 0;
  for (let offset = 0; offset < subscribers.rows.length; offset += 100) {
    const batch = subscribers.rows.slice(offset, offset + 100);
    const messages = [];
    for (const subscriber of batch) {
      const unsubscribeToken = randomBytes(32).toString("base64url");
      const unsubscribeUrl = `${config.publicSiteUrl}/newsletter-unsubscribe.html?token=${encodeURIComponent(unsubscribeToken)}`;
      const articleUrl = `${config.publicSiteUrl}/news.html#${encodeURIComponent(article.id)}`;
      await pool.query(
        `INSERT INTO newsletter_unsubscribe_tokens (token_hash, subscription_id)
         VALUES ($1, $2)`,
        [hashToken(unsubscribeToken), subscriber.id]
      );
      await pool.query(
        `INSERT INTO news_email_deliveries (article_id, subscription_id, status)
         VALUES ($1, $2, 'pending')
         ON CONFLICT (article_id, subscription_id) DO UPDATE
         SET status = 'pending', error_message = NULL, updated_at = NOW()
         WHERE news_email_deliveries.status <> 'sent'`,
        [article.id, subscriber.id]
      );
      messages.push({
        to: subscriber.email,
        subject: `UBUZIMA PHARMA: ${article.title}`,
        html: newsletterEmailHtml(article, articleUrl, unsubscribeUrl),
        text: `${article.title}\n\n${article.summary}\n\nSoma inkuru yose: ${articleUrl}${article.video_url ? `\nRaba videwo: ${article.video_url}` : ""}\n\nHagarika kwakira aya makuru: ${unsubscribeUrl}`,
        subscriptionId: subscriber.id
      });
    }

    for (const message of messages) {
      let deliveryError;
      try {
        await sendEmailBatch([message]);
      } catch (error) {
        deliveryError = error;
      }

      if (deliveryError) {
        await pool.query(
          `UPDATE news_email_deliveries
           SET status = 'failed', error_message = $3, updated_at = NOW()
           WHERE article_id = $1 AND subscription_id = $2 AND status <> 'sent'`,
          [article.id, message.subscriptionId, deliveryError.message.slice(0, 500)]
        );
        failed += 1;
      } else {
        await pool.query(
          `UPDATE news_email_deliveries
           SET status = 'sent', error_message = NULL, sent_at = NOW(), updated_at = NOW()
           WHERE article_id = $1 AND subscription_id = $2`,
          [article.id, message.subscriptionId]
        );
        sent += 1;
      }
    }
  }
  return { status: failed ? "partial" : "sent", sent, failed, pending: 0 };
}

function logoutSession(req, res, next) {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie(SESSION_COOKIE, {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: config.sameSite
    });
    return res.status(204).end();
  });
}

function fetchOrderDetails(orderIds) {
  if (!orderIds.length) return Promise.resolve({ rows: [] });
  return pool.query(
    `SELECT order_id, product_id, product_name, quantity, unit_price_bif
     FROM patient_order_items WHERE order_id = ANY($1::uuid[]) ORDER BY id`,
    [orderIds]
  );
}

export function createApp() {
  const app = express();
  const scheduledPublisher = setInterval(() => {
    publishScheduledContent().catch(error => console.error("Could not publish scheduled content.", error));
  }, 60_000);
  scheduledPublisher.unref();
  publishScheduledContent().catch(error => console.error("Could not publish scheduled content.", error));
  app.param("id", (req, res, next, id) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
      return res.status(400).json({ error: "ID is invalid." });
    }
    return next();
  });
  app.disable("x-powered-by");
  if (config.trustProxy) app.set("trust proxy", 1);
  app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
  app.use(cors({
    origin(origin, callback) {
      if (!origin || config.corsOrigins.has(origin) || isDevelopmentOrigin(origin)) return callback(null, true);
      return callback(Object.assign(new Error("Origin is not allowed."), { status: 403 }));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-CSRF-Token"],
    maxAge: 600
  }));
  app.use(express.json({ limit: "256kb" }));
  app.use(session({
    name: SESSION_COOKIE,
    secret: config.sessionSecret,
    store: new PgSession({
      pool,
      tableName: "pharmacy_sessions",
      createTableIfMissing: true,
      pruneSessionInterval: 15 * 60
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: config.sameSite,
      maxAge: 8 * 60 * 60 * 1000
    }
  }));
  app.use("/uploads", express.static(config.uploadDirectory, {
    fallthrough: false,
    index: false,
    dotfiles: "deny",
    maxAge: config.isProduction ? "7d" : 0,
    immutable: config.isProduction
  }));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many sign-in attempts. Try again later." }
  });

  app.get("/health", asyncRoute(async (_req, res) => {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  }));

  app.get("/api/products", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
              pack_size, manufacturer, directions_for_use, warnings, storage_instructions,
              indications, price_bif, stock_quantity, image_url, is_available, created_at, updated_at
       FROM products WHERE is_available = TRUE ORDER BY name`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows.map(publicProduct));
  }));

  const issueCsrf = (req, res) => {
    req.session.csrfToken ||= randomBytes(32).toString("hex");
    res.set("Cache-Control", "no-store");
    res.json({ csrfToken: req.session.csrfToken });
  };
  app.get("/api/auth/csrf", issueCsrf);
  app.get("/api/admin/csrf", issueCsrf);

  app.post("/api/auth/password/forgot", passwordResetRequestLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const accountType = req.body?.account_type;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !["staff", "patient"].includes(accountType)) {
      return res.status(400).json({ error: "Enter a valid email address and account type." });
    }
    if (!emailIsConfigured()) throw emailConfigurationError();

    let matchedAccountType = accountType;
    let accountQuery = matchedAccountType === "staff"
      ? await pool.query("SELECT id FROM staff_users WHERE username = $1 AND is_active = TRUE", [email])
      : await pool.query("SELECT id FROM patient_users WHERE email = $1 AND is_active = TRUE", [email]);
    if (!accountQuery.rowCount) {
      matchedAccountType = matchedAccountType === "staff" ? "patient" : "staff";
      accountQuery = matchedAccountType === "staff"
        ? await pool.query("SELECT id FROM staff_users WHERE username = $1 AND is_active = TRUE", [email])
        : await pool.query("SELECT id FROM patient_users WHERE email = $1 AND is_active = TRUE", [email]);
    }
    if (accountQuery.rowCount) {
      const accountId = accountQuery.rows[0].id;
      const token = randomBytes(32).toString("base64url");
      const tokenHash = hashToken(token);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          matchedAccountType === "staff"
            ? "UPDATE password_reset_tokens SET used_at = NOW() WHERE staff_user_id = $1 AND used_at IS NULL"
            : "UPDATE password_reset_tokens SET used_at = NOW() WHERE patient_user_id = $1 AND used_at IS NULL",
          [accountId]
        );
        await client.query(
          `INSERT INTO password_reset_tokens (id, token_hash, staff_user_id, patient_user_id, expires_at)
           VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')`,
          [randomUUID(), tokenHash, matchedAccountType === "staff" ? accountId : null, matchedAccountType === "patient" ? accountId : null]
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

      const resetUrl = `${config.publicSiteUrl}/password-reset.html?account_type=${matchedAccountType}&token=${encodeURIComponent(token)}`;
      try {
        await sendEmailBatch([{
          to: email,
          subject: "Guhindura ijambobanga ryawe - UBUZIMA PHARMA",
          html: `<p>Twaronse igisabo co guhindura ijambobanga rya konti yawe ya UBUZIMA PHARMA.</p><p><a href="${resetUrl}">Hindura ijambobanga</a></p><p>Iyi link iramara isaha imwe kandi ikoreshwa rimwe gusa. Nimba utabisavye, wirengagize ubu butumwa.</p>`,
          text: `Hindura ijambobanga rya konti yawe ya UBUZIMA PHARMA: ${resetUrl}\nIyi link iramara isaha imwe kandi ikoreshwa rimwe gusa. Nimba utabisavye, wirengagize ubu butumwa.`
        }]);
      } catch (error) {
        await pool.query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1", [tokenHash]);
        console.error("Could not send a password recovery email.", error);
      }
    }

    res.set("Cache-Control", "no-store");
    return res.status(202).json({
      message: "Nimba konti ikoresha iyo email iriho, tuzorungika link yo guhindura ijambobanga."
    });
  }));

  app.post("/api/auth/password/reset", passwordResetLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    const accountType = req.body?.account_type;
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!/^[A-Za-z0-9_-]{40,50}$/.test(token) || !["staff", "patient"].includes(accountType)) {
      return res.status(400).json({ error: "Password reset link is invalid or expired." });
    }
    if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ error: "Password must be at least 12 characters and no more than 72 UTF-8 bytes." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const tokenResult = await client.query(
        `SELECT id, staff_user_id, patient_user_id
         FROM password_reset_tokens
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
           AND (($2 = 'staff' AND staff_user_id IS NOT NULL) OR ($2 = 'patient' AND patient_user_id IS NOT NULL))
         FOR UPDATE`,
        [hashToken(token), accountType]
      );
      if (!tokenResult.rowCount) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Password reset link is invalid or expired." });
      }

      const reset = tokenResult.rows[0];
      const accountId = accountType === "staff" ? reset.staff_user_id : reset.patient_user_id;
      const passwordHash = await bcrypt.hash(password, 12);
      const updated = accountType === "staff"
        ? await client.query("UPDATE staff_users SET password_hash = $2 WHERE id = $1 AND is_active = TRUE", [accountId, passwordHash])
        : await client.query("UPDATE patient_users SET password_hash = $2 WHERE id = $1 AND is_active = TRUE", [accountId, passwordHash]);
      if (!updated.rowCount) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Password reset link is invalid or expired." });
      }

      await client.query("UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1", [reset.id]);
      await client.query(
        accountType === "staff"
          ? "UPDATE password_reset_tokens SET used_at = NOW() WHERE staff_user_id = $1 AND used_at IS NULL"
          : "UPDATE password_reset_tokens SET used_at = NOW() WHERE patient_user_id = $1 AND used_at IS NULL",
        [accountId]
      );
      await client.query(
        accountType === "staff"
          ? "DELETE FROM pharmacy_sessions WHERE sess->>'staffId' = $1"
          : "DELETE FROM pharmacy_sessions WHERE sess->>'patientId' = $1",
        [accountId]
      );
      await client.query("COMMIT");
      res.set("Cache-Control", "no-store");
      return res.json({ message: "Ijambobanga ryawe ryahinduwe. Injira ukoresheje irishasha." });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/api/news", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT articles.id, articles.title, articles.summary, articles.body, articles.category, articles.image_url,
              articles.video_url, articles.views_count,
              articles.published_at, users.username AS author
       FROM news_articles articles LEFT JOIN staff_users users ON users.id = articles.author_id
       WHERE articles.status = 'published'
       ORDER BY articles.published_at DESC LIMIT 50`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows.map(article => ({ ...article, body: sanitizeArticleHtml(article.body) })));
  }));

  app.get("/api/videos", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT id, title, description, category, source_type, video_url, thumbnail_url,
              views_count, published_at
       FROM videos WHERE status = 'published'
       ORDER BY published_at DESC LIMIT 50`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.post("/api/videos/:id/view", requireCsrf, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `UPDATE videos SET views_count = views_count + 1
       WHERE id = $1 AND status = 'published' RETURNING views_count`,
      [req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Published video not found." });
    return res.json({ views_count: result.rows[0].views_count });
  }));

  app.post("/api/news/:id/view", requireCsrf, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `UPDATE news_articles SET views_count = views_count + 1
       WHERE id = $1 AND status = 'published' RETURNING views_count`,
      [req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Published news article not found." });
    return res.json({ views_count: result.rows[0].views_count });
  }));

  app.post("/api/newsletter/subscribe", newsletterLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    await pool.query(
      `INSERT INTO newsletter_subscriptions (id, email, is_verified, is_subscribed, verified_at)
       VALUES ($1, $2, TRUE, TRUE, NOW())
       ON CONFLICT (email) DO UPDATE
       SET is_verified = TRUE, is_subscribed = TRUE, verified_at = NOW(),
           verification_token_hash = NULL, unsubscribed_at = NULL`,
      [randomUUID(), email]
    );
    return res.json({ message: "Wiyandikishije kwakira amakuru mashasha ya UBUZIMA PHARMA." });
  }));

  app.post("/api/newsletter/confirm", requireCsrf, asyncRoute(async (req, res) => {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    if (!/^[A-Za-z0-9_-]{40,50}$/.test(token)) return res.status(400).json({ error: "Confirmation link is invalid or expired." });
    const result = await pool.query(
      `UPDATE newsletter_subscriptions
       SET is_verified = TRUE, is_subscribed = TRUE, verified_at = NOW(),
           unsubscribed_at = NULL, verification_token_hash = NULL
       WHERE verification_token_hash = $1 AND is_subscribed = TRUE
       RETURNING id`,
      [hashToken(token)]
    );
    if (!result.rowCount) return res.status(400).json({ error: "Confirmation link is invalid or expired." });
    return res.json({ message: "Kwiyandikisha kwawe kwemejwe. Urashobora guhagarika kwakira amakuru igihe cose." });
  }));

  app.post("/api/newsletter/unsubscribe", requireCsrf, asyncRoute(async (req, res) => {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    if (!/^[A-Za-z0-9_-]{40,50}$/.test(token)) return res.status(400).json({ error: "Unsubscribe link is invalid." });
    const result = await pool.query(
      `UPDATE newsletter_subscriptions SET is_subscribed = FALSE, unsubscribed_at = NOW()
       WHERE id = (SELECT subscription_id FROM newsletter_unsubscribe_tokens WHERE token_hash = $1)
       RETURNING id`,
      [hashToken(token)]
    );
    if (!result.rowCount) return res.status(400).json({ error: "Unsubscribe link is invalid or expired." });
    return res.json({ message: "Wahagaritse kwakira amakuru mashasha ya UBUZIMA PHARMA." });
  }));

  app.post("/api/staff/invitations/accept", requireCsrf, asyncRoute(async (req, res) => {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!/^[A-Za-z0-9_-]{40,50}$/.test(token)) return res.status(400).json({ error: "Invitation link is invalid or expired." });
    if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ error: "Password must be at least 12 characters and no more than 72 UTF-8 bytes." });
    }

    const client = await pool.connect();
    let staff;
    try {
      await client.query("BEGIN");
      const invitation = await client.query(
        `SELECT id, email, role FROM staff_invitations
         WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > NOW() FOR UPDATE`,
        [hashToken(token)]
      );
      if (!invitation.rowCount) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invitation link is invalid or expired." });
      }
      const account = invitation.rows[0];
      const passwordHash = await bcrypt.hash(password, 12);
      const created = await client.query(
        `INSERT INTO staff_users (id, username, password_hash, role, full_name)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role, full_name, phone, profile_image_url`,
        [randomUUID(), account.email, passwordHash, account.role, account.email]
      );
      await client.query("UPDATE staff_invitations SET accepted_at = NOW() WHERE id = $1", [account.id]);
      await client.query("COMMIT");
      staff = created.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return res.status(409).json({ error: "A staff account already exists for this email." });
      throw error;
    } finally {
      client.release();
    }

    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.staffId = staff.id;
    req.session.staffUsername = staff.username;
    req.session.csrfToken = randomBytes(32).toString("hex");
    return res.status(201).json({
      staff: { username: staff.username, role: staff.role, full_name: staff.full_name, phone: staff.phone, profile_image_url: staff.profile_image_url },
      csrfToken: req.session.csrfToken
    });
  }));

  const staffLogin = async (req, res, expectedRole) => {
    const email = typeof req.body?.email === "string"
      ? req.body.email.trim().toLowerCase()
      : typeof req.body?.username === "string" ? req.body.username.trim().toLowerCase() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !password || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ error: "Enter a valid email address and password." });
    }

    const result = await pool.query(
      "SELECT id, username, password_hash, role, full_name, phone, profile_image_url FROM staff_users WHERE username = $1 AND is_active = TRUE",
      [email]
    );
    const staff = result.rows[0];
    const validPassword = await bcrypt.compare(password, staff?.password_hash || DUMMY_PASSWORD_HASH);
    if (!staff || !validPassword || staff.role !== expectedRole) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }

    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.staffId = staff.id;
    req.session.staffUsername = staff.username;
    req.session.csrfToken = randomBytes(32).toString("hex");
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    res.set("Cache-Control", "no-store");
    return res.json({ staff: { username: staff.username, role: staff.role, full_name: staff.full_name, phone: staff.phone, profile_image_url: staff.profile_image_url }, csrfToken: req.session.csrfToken });
  };
  app.post("/api/staff/login", loginLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const role = req.body?.role;
    if (!["admin", "pharmacist", "doctor"].includes(role)) return res.status(400).json({ error: "Choose a valid staff portal." });
    return staffLogin(req, res, role);
  }));
  app.post("/api/admin/login", loginLimiter, requireCsrf, asyncRoute((req, res) => staffLogin(req, res, "admin")));
  app.post("/api/pharmacist/login", loginLimiter, requireCsrf, asyncRoute((req, res) => staffLogin(req, res, "pharmacist")));
  app.post("/api/doctor/login", loginLimiter, requireCsrf, asyncRoute((req, res) => staffLogin(req, res, "doctor")));

  app.get("/api/staff/session", requireStaff, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ staff: { username: req.staffUser.username, role: req.staffUser.role, full_name: req.staffUser.full_name, phone: req.staffUser.phone, profile_image_url: req.staffUser.profile_image_url } });
  });
  app.get("/api/admin/session", requireStaff, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ staff: { username: req.staffUser.username, role: req.staffUser.role, full_name: req.staffUser.full_name, phone: req.staffUser.phone, profile_image_url: req.staffUser.profile_image_url } });
  });

  app.patch("/api/staff/profile", requireStaff, requireCsrfForMutation, upload.single("image"), asyncRoute(async (req, res) => {
    const validated = validateProfileDetails(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (req.body.remove_profile_image === "true" && req.file) {
      return res.status(400).json({ error: "Upload a new photo or remove the current photo, not both." });
    }
    const profileImageUrl = req.body.remove_profile_image === "true"
      ? null
      : req.file ? (await writeImage(req.file.buffer)).url : req.staffUser.profile_image_url;
    const result = await pool.query(
      `UPDATE staff_users SET full_name = $2, phone = $3, profile_image_url = $4
       WHERE id = $1 RETURNING id, username, role, full_name, phone, profile_image_url`,
      [req.staffUser.id, validated.value.fullName, validated.value.phone, profileImageUrl]
    );
    res.set("Cache-Control", "no-store");
    return res.json({ staff: result.rows[0] });
  }));
  app.get("/api/staff/profile", requireStaff, (req, res) => {
    res.set("Cache-Control", "no-store");
    return res.json({ staff: req.staffUser });
  });

  app.post("/api/staff/sales", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation, salesUpload.single("image"), asyncRoute(async (req, res) => {
    const rawAmount = typeof req.body?.amount_bif === "string" ? req.body.amount_bif.trim() : "";
    if (!/^\d{1,14}$/.test(rawAmount) || Number(rawAmount) < 1 || !Number.isSafeInteger(Number(rawAmount))) {
      return res.status(400).json({ error: "Enter the sale amount as a positive whole number of BIF." });
    }
    const rawSaleDate = typeof req.body?.sale_date === "string" ? req.body.sale_date.trim() : "";
    const validSaleDate = /^\d{4}-\d{2}-\d{2}$/.test(rawSaleDate) && !Number.isNaN(Date.parse(`${rawSaleDate}T00:00:00Z`)) && new Date(`${rawSaleDate}T00:00:00Z`).toISOString().slice(0, 10) === rawSaleDate;
    if (rawSaleDate && !validSaleDate) {
      return res.status(400).json({ error: "Choose a valid sale date." });
    }
    const filename = await storeSalesImage(req.file);
    try {
      const result = await pool.query(
        `INSERT INTO pharmacy_sales (id, staff_user_id, amount_bif, sale_date, image_filename)
         VALUES ($1, $2, $3, COALESCE($4::date, timezone('Africa/Bujumbura', NOW())::date), $5)
         RETURNING id, amount_bif, sale_date, created_at`,
        [randomUUID(), req.staffUser.id, rawAmount, rawSaleDate || null, filename]
      );
      res.set("Cache-Control", "no-store");
      return res.status(201).json(result.rows[0]);
    } catch (error) {
      await fs.unlink(path.join(config.salesDirectory, filename)).catch(() => {});
      throw error;
    }
  }));

  app.get("/api/staff/sales", requireStaff, requireAnyRole("admin", "pharmacist"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id, amount_bif, sale_date::text, created_at
       FROM pharmacy_sales
       WHERE $1 = 'admin' OR staff_user_id = $2
       ORDER BY created_at DESC LIMIT 100`,
      [req.staffUser.role, req.staffUser.id]
    );
    res.set("Cache-Control", "no-store, private");
    return res.json(result.rows.map(row => ({ ...row, amount_bif: Number(row.amount_bif) })));
  }));

  app.delete("/api/staff/sales/:id", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.id)) {
      return res.status(404).json({ error: "Sale not found or you do not have permission to delete it." });
    }
    const result = await pool.query(
      `DELETE FROM pharmacy_sales
       WHERE id = $1 AND ($2 = 'admin' OR staff_user_id = $3)
       RETURNING image_filename`,
      [req.params.id, req.staffUser.role, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Sale not found or you do not have permission to delete it." });
    await fs.unlink(path.join(config.salesDirectory, result.rows[0].image_filename)).catch(error => {
      if (error.code !== "ENOENT") console.error("Could not remove deleted sale photo.", error);
    });
    res.set("Cache-Control", "no-store");
    return res.status(204).end();
  }));

  app.get("/api/admin/earnings", requireStaff, requireRole("admin"), asyncRoute(async (req, res) => {
    const datePattern = /^\d{4}-\d{2}-\d{2}$/;
    const validDate = value => datePattern.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;
    const todayResult = await pool.query("SELECT timezone('Africa/Bujumbura', NOW())::date::text AS today");
    const today = todayResult.rows[0].today;
    const from = typeof req.query.from === "string" ? req.query.from : today;
    const to = typeof req.query.to === "string" ? req.query.to : today;
    if (!validDate(from) || !validDate(to) || from > to) return res.status(400).json({ error: "Choose a valid date range." });
    const days = Math.floor((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86400000) + 1;
    if (days > 366) return res.status(400).json({ error: "Date range cannot exceed 366 days." });
    const result = await pool.query(
      `WITH daily_sales AS (
         SELECT sale_date, SUM(amount_bif)::NUMERIC(14,0) AS sales_bif, COUNT(*)::INTEGER AS entries
         FROM pharmacy_sales WHERE sale_date BETWEEN $1::date AND $2::date GROUP BY sale_date
       ), days AS (
         SELECT day::date AS sale_date FROM generate_series($1::date, $2::date, INTERVAL '1 day') day
       )
       SELECT days.sale_date::text, COALESCE(daily_sales.sales_bif, 0)::NUMERIC(14,0) AS sales_bif,
              COALESCE(daily_sales.entries, 0)::INTEGER AS entries
       FROM days LEFT JOIN daily_sales USING (sale_date) ORDER BY days.sale_date DESC`,
      [from, to]
    );
    const dailyFixedExpense = 500000 / 30;
    const daysData = result.rows.map(row => {
      const sales = Number(row.sales_bif);
      const grossProfit = sales / 3;
      return {
        date: row.sale_date,
        sales_bif: sales,
        gross_profit_bif: Math.round(grossProfit * 100) / 100,
        fixed_expense_bif: Math.round(dailyFixedExpense * 100) / 100,
        earnings_bif: Math.round((grossProfit - dailyFixedExpense) * 100) / 100,
        entries: row.entries
      };
    });
    const totals = daysData.reduce((sum, day) => ({
      sales_bif: sum.sales_bif + day.sales_bif,
      gross_profit_bif: sum.gross_profit_bif + day.gross_profit_bif,
      fixed_expense_bif: sum.fixed_expense_bif + day.fixed_expense_bif,
      earnings_bif: sum.earnings_bif + day.earnings_bif,
      entries: sum.entries + day.entries
    }), { sales_bif: 0, gross_profit_bif: 0, fixed_expense_bif: 0, earnings_bif: 0, entries: 0 });
    const sales = await pool.query(
      `SELECT sales.id, sales.amount_bif, sales.sale_date::text, sales.created_at,
              users.full_name AS staff_name
       FROM pharmacy_sales sales LEFT JOIN staff_users users ON users.id = sales.staff_user_id
       WHERE sales.sale_date BETWEEN $1::date AND $2::date
       ORDER BY sales.created_at DESC LIMIT 500`,
      [from, to]
    );
    res.set("Cache-Control", "no-store, private");
    return res.json({
      currency: "BIF", range: { from, to },
      assumptions: { monthly_salary_bif: 200000, monthly_rent_bif: 300000, daily_fixed_expense_bif: Math.round(dailyFixedExpense * 100) / 100, gross_margin: 1 / 3 },
      totals, days: daysData,
      sales: sales.rows.map(row => ({ ...row, amount_bif: Number(row.amount_bif), image_url: `/api/admin/earnings/${row.id}/image` }))
    });
  }));

  app.get("/api/admin/earnings/:id/image", requireStaff, requireRole("admin"), asyncRoute(async (req, res) => {
    const result = await pool.query("SELECT image_filename FROM pharmacy_sales WHERE id = $1", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: "Sale photo not found." });
    res.set({ "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff" });
    return res.type("image/webp").sendFile(path.join(config.salesDirectory, result.rows[0].image_filename));
  }));

  app.post("/api/staff/logout", requireStaff, requireCsrf, logoutSession);
  app.post("/api/admin/logout", requireStaff, requireCsrf, logoutSession);

  const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many registration attempts. Try again later." }
  });
  app.post("/api/patient/register", registrationLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const validated = validatePatientRegistration(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const passwordHash = await bcrypt.hash(validated.value.password, 12);
    const id = randomUUID();
    try {
      await pool.query(
        `INSERT INTO patient_users (id, email, full_name, phone, password_hash)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, validated.value.email, validated.value.fullName, validated.value.phone, passwordHash]
      );
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "An account with this email already exists." });
      throw error;
    }
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.patientId = id;
    req.session.csrfToken = randomBytes(32).toString("hex");
    res.set("Cache-Control", "no-store");
    return res.status(201).json({
      patient: { id, email: validated.value.email, full_name: validated.value.fullName, phone: validated.value.phone, profile_image_url: null },
      csrfToken: req.session.csrfToken
    });
  }));

  app.post("/api/patient/login", loginLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!email || email.length > 254 || !password || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ error: "Enter a valid email address and password." });
    }
    const result = await pool.query(
      "SELECT id, email, full_name, phone, profile_image_url, password_hash FROM patient_users WHERE email = $1 AND is_active = TRUE",
      [email]
    );
    const patient = result.rows[0];
    const validPassword = await bcrypt.compare(password, patient?.password_hash || DUMMY_PASSWORD_HASH);
    if (!patient || !validPassword) return res.status(401).json({ error: "Email or password is incorrect." });
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.patientId = patient.id;
    req.session.csrfToken = randomBytes(32).toString("hex");
    res.set("Cache-Control", "no-store");
    return res.json({
      patient: { id: patient.id, email: patient.email, full_name: patient.full_name, phone: patient.phone, profile_image_url: patient.profile_image_url },
      csrfToken: req.session.csrfToken
    });
  }));

  app.get("/api/patient/session", requirePatient, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ patient: req.patientUser });
  });
  app.post("/api/patient/logout", requirePatient, requireCsrf, logoutSession);
  app.use("/api/patient", requirePatient, requireCsrfForMutation);

  app.patch("/api/patient/profile", upload.single("image"), asyncRoute(async (req, res) => {
    const validated = validateProfileDetails(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (req.body.remove_profile_image === "true" && req.file) {
      return res.status(400).json({ error: "Upload a new photo or remove the current photo, not both." });
    }
    const profileImageUrl = req.body.remove_profile_image === "true"
      ? null
      : req.file ? (await writeImage(req.file.buffer)).url : req.patientUser.profile_image_url;
    const result = await pool.query(
      `UPDATE patient_users SET full_name = $2, phone = $3, profile_image_url = $4
       WHERE id = $1 RETURNING id, email, full_name, phone, profile_image_url`,
      [req.patientUser.id, validated.value.fullName, validated.value.phone, profileImageUrl]
    );
    res.set("Cache-Control", "no-store");
    return res.json({ patient: result.rows[0] });
  }));

  app.get("/api/patient/care-requests", asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT requests.id, requests.treatment_location, requests.treated_on, requests.status,
              requests.doctor_consultation_status, requests.doctor_scheduled_at,
              requests.doctor_meeting_url, doctor.username AS doctor_name,
              requests.prescription_filename IS NOT NULL AS has_prescription,
              requests.created_at, requests.updated_at
       FROM patient_care_requests requests
       LEFT JOIN staff_users doctor ON doctor.id = requests.assigned_doctor_id
       WHERE requests.patient_id = $1 ORDER BY requests.created_at DESC`,
      [req.patientUser.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows.map(request => ({
      ...request,
      doctor_meeting_url: request.doctor_consultation_status === "scheduled" ? doctorCallUrl(request.id) : null
    })));
  }));

  app.get("/api/patient/care-requests/:id/call", asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id, doctor_consultation_status AS status, doctor_scheduled_at,
              doctor_duration_minutes
       FROM patient_care_requests
       WHERE id = $1 AND patient_id = $2 AND doctor_consultation_status = 'scheduled'`,
      [req.params.id, req.patientUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Booked consultation not found." });
    res.set("Cache-Control", "no-store");
    return res.json({ ...result.rows[0], role: "patient", call_url: doctorCallUrl(req.params.id), ice_servers: config.rtcIceServers });
  }));

  app.get("/api/patient/care-requests/:id/call/signals", asyncRoute(async (req, res) => {
    const after = callSignalCursor(req, res);
    if (after === null) return;
    const result = await pool.query(
      `SELECT signals.id::text AS id, signals.signal
       FROM doctor_call_signals signals
       JOIN patient_care_requests requests ON requests.id = signals.care_request_id
       WHERE signals.care_request_id = $1 AND requests.patient_id = $2
         AND requests.doctor_consultation_status = 'scheduled'
         AND signals.recipient_role = 'patient' AND signals.id > $3::bigint
       ORDER BY signals.id LIMIT 100`,
      [req.params.id, req.patientUser.id, after]
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows);
  }));

  app.post("/api/patient/care-requests/:id/call/signals", asyncRoute(async (req, res) => {
    const validated = validateCallSignal(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const result = await pool.query(
      `INSERT INTO doctor_call_signals (care_request_id, sender_role, recipient_role, signal)
       SELECT requests.id, 'patient', 'doctor', $3::jsonb
       FROM patient_care_requests requests
       WHERE requests.id = $1 AND requests.patient_id = $2
         AND requests.doctor_consultation_status = 'scheduled'
       RETURNING id::text AS id`,
      [req.params.id, req.patientUser.id, JSON.stringify(validated.value)]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Booked consultation not found." });
    await pool.query("DELETE FROM doctor_call_signals WHERE created_at < NOW() - INTERVAL '1 day'");
    return res.status(201).json({ id: result.rows[0].id });
  }));

  app.post("/api/patient/care-requests", prescriptionUpload.single("prescription"), asyncRoute(async (req, res) => {
    const location = typeof req.body?.treatment_location === "string" ? req.body.treatment_location.trim() : "";
    const treatedOn = typeof req.body?.treated_on === "string" ? req.body.treated_on : "";
    const doctorRequested = req.body?.request_doctor === "true";
    if (!location || location.length > 180) return res.status(400).json({ error: "Treatment location is required and must be at most 180 characters." });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(treatedOn) || !Number.isFinite(Date.parse(`${treatedOn}T00:00:00Z`)) || new Date(`${treatedOn}T00:00:00Z`).toISOString().slice(0, 10) !== treatedOn) {
      return res.status(400).json({ error: "Enter a valid treatment date." });
    }
    if (treatedOn > new Date().toISOString().slice(0, 10)) return res.status(400).json({ error: "Treatment date cannot be in the future." });
    if (req.body?.request_doctor !== undefined && !["true", "false"].includes(req.body.request_doctor)) {
      return res.status(400).json({ error: "Doctor consultation choice is invalid." });
    }
    const prescription = await storePrescription(req.file);
    const id = randomUUID();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO patient_care_requests
           (id, patient_id, treatment_location, treated_on, prescription_filename,
            prescription_mime_type, doctor_consultation_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, req.patientUser.id, location, treatedOn, prescription?.filename || null,
          prescription?.mimeType || null, doctorRequested ? "requested" : "not_requested"]
      );
      await client.query(
        `INSERT INTO doctor_consultation_messages (care_request_id, sender_patient_id, message)
         SELECT $1, $2, 'The patient requested a doctor consultation.' WHERE $3 = TRUE`,
        [id, req.patientUser.id, doctorRequested]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      await deletePrescription(prescription?.filename);
      throw error;
    } finally {
      client.release();
    }
    res.set("Cache-Control", "no-store");
    return res.status(201).json({ id, treatment_location: location, treated_on: treatedOn,
      status: "open", doctor_consultation_status: doctorRequested ? "requested" : "not_requested",
      has_prescription: Boolean(prescription) });
  }));

  app.get("/api/patient/care-requests/:id/doctor-messages", asyncRoute(async (req, res) => {
    const owned = await pool.query(
      "SELECT id FROM patient_care_requests WHERE id = $1 AND patient_id = $2 AND assigned_doctor_id IS NOT NULL",
      [req.params.id, req.patientUser.id]
    );
    if (!owned.rowCount) return res.status(404).json({ error: "Assigned doctor consultation not found." });
    const messages = await pool.query(
      `SELECT messages.id, messages.message, messages.created_at,
              CASE WHEN messages.sender_patient_id IS NULL THEN 'doctor' ELSE 'patient' END AS sender,
              COALESCE(doctor.username, patients.full_name) AS sender_name
       FROM doctor_consultation_messages messages
       LEFT JOIN staff_users doctor ON doctor.id = messages.sender_doctor_id
       LEFT JOIN patient_users patients ON patients.id = messages.sender_patient_id
       WHERE messages.care_request_id = $1 ORDER BY messages.created_at, messages.id`,
      [req.params.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(messages.rows);
  }));

  app.post("/api/patient/care-requests/:id/doctor-messages", asyncRoute(async (req, res) => {
    const validated = validateCareMessage(req.body?.message);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const owned = await pool.query(
      `SELECT id FROM patient_care_requests WHERE id = $1 AND patient_id = $2
       AND assigned_doctor_id IS NOT NULL AND doctor_consultation_status <> 'completed'`,
      [req.params.id, req.patientUser.id]
    );
    if (!owned.rowCount) return res.status(404).json({ error: "Active assigned doctor consultation not found." });
    const result = await pool.query(
      `INSERT INTO doctor_consultation_messages (care_request_id, sender_patient_id, message)
       VALUES ($1, $2, $3) RETURNING id, message, created_at`,
      [req.params.id, req.patientUser.id, validated.value]
    );
    await pool.query("UPDATE patient_care_requests SET updated_at = NOW() WHERE id = $1", [req.params.id]);
    res.set("Cache-Control", "no-store");
    return res.status(201).json({ ...result.rows[0], sender: "patient" });
  }));

  app.get("/api/patient/care-requests/:id/messages", asyncRoute(async (req, res) => {
    const owned = await pool.query("SELECT id FROM patient_care_requests WHERE id = $1 AND patient_id = $2", [req.params.id, req.patientUser.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "Care request not found." });
    const messages = await pool.query(
      `SELECT messages.id, messages.message, messages.created_at,
              CASE WHEN messages.sender_patient_id IS NULL THEN 'staff' ELSE 'patient' END AS sender
       FROM patient_care_messages messages WHERE messages.request_id = $1 ORDER BY messages.created_at, messages.id`,
      [req.params.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(messages.rows);
  }));

  app.post("/api/patient/care-requests/:id/messages", asyncRoute(async (req, res) => {
    const validated = validateCareMessage(req.body?.message);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const owned = await pool.query("SELECT id, status FROM patient_care_requests WHERE id = $1 AND patient_id = $2", [req.params.id, req.patientUser.id]);
    if (!owned.rowCount) return res.status(404).json({ error: "Care request not found." });
    if (owned.rows[0].status === "closed") return res.status(409).json({ error: "This care request is closed." });
    const result = await pool.query(
      `INSERT INTO patient_care_messages (request_id, sender_patient_id, message)
       VALUES ($1, $2, $3) RETURNING id, message, created_at`,
      [req.params.id, req.patientUser.id, validated.value]
    );
    await pool.query("UPDATE patient_care_requests SET updated_at = NOW() WHERE id = $1", [req.params.id]);
    res.set("Cache-Control", "no-store");
    return res.status(201).json({ ...result.rows[0], sender: "patient" });
  }));

  app.get("/api/patient/care-requests/:id/prescription", asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT prescription_filename, prescription_mime_type FROM patient_care_requests
       WHERE id = $1 AND patient_id = $2 AND prescription_filename IS NOT NULL`,
      [req.params.id, req.patientUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Prescription not found." });
    res.set({ "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff" });
    return res.type(result.rows[0].prescription_mime_type).download(path.join(config.patientCareDirectory, result.rows[0].prescription_filename));
  }));

  app.get("/api/patient/orders", asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id, status, total_bif, created_at, updated_at
       FROM patient_orders WHERE patient_id = $1 ORDER BY created_at DESC`,
      [req.patientUser.id]
    );
    const details = await fetchOrderDetails(result.rows.map(order => order.id));
    const itemsByOrder = new Map();
    for (const item of details.rows) {
      const items = itemsByOrder.get(item.order_id) || [];
      items.push({
        product_id: item.product_id,
        product_name: item.product_name,
        quantity: item.quantity,
        unit_price_bif: Number(item.unit_price_bif)
      });
      itemsByOrder.set(item.order_id, items);
    }
    res.set("Cache-Control", "no-store");
    res.json(result.rows.map(order => ({
      ...order,
      total_bif: Number(order.total_bif),
      items: itemsByOrder.get(order.id) || []
    })));
  }));

  app.post("/api/patient/orders", asyncRoute(async (req, res) => {
    const validated = validateOrderItems(req.body?.items);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const ids = validated.value.map(item => item.productId);
      const productsResult = await client.query(
        `SELECT id, name, price_bif, stock_quantity, is_available
         FROM products WHERE id = ANY($1::uuid[]) FOR UPDATE`,
        [ids]
      );
      if (productsResult.rowCount !== ids.length) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "One or more products are no longer available." });
      }
      const productsById = new Map(productsResult.rows.map(product => [product.id, product]));
      let totalBif = 0n;
      for (const item of validated.value) {
        const product = productsById.get(item.productId);
        if (!product.is_available || product.price_bif === null || product.stock_quantity < item.quantity) {
          await client.query("ROLLBACK");
          return res.status(409).json({ error: `${product.name} is unavailable, has no listed price, or has insufficient stock.` });
        }
        totalBif += BigInt(product.price_bif) * BigInt(item.quantity);
      }
      if (totalBif > 99999999999999n) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Order total exceeds the supported limit." });
      }
      const orderId = randomUUID();
      await client.query(
        "INSERT INTO patient_orders (id, patient_id, total_bif) VALUES ($1, $2, $3)",
        [orderId, req.patientUser.id, totalBif.toString()]
      );
      for (const item of validated.value) {
        const product = productsById.get(item.productId);
        await client.query(
          `INSERT INTO patient_order_items (order_id, product_id, product_name, quantity, unit_price_bif)
           VALUES ($1, $2, $3, $4, $5)`,
          [orderId, product.id, product.name, item.quantity, product.price_bif]
        );
        await client.query(
          "UPDATE products SET stock_quantity = stock_quantity - $2, updated_at = NOW() WHERE id = $1",
          [product.id, item.quantity]
        );
      }
      await client.query("COMMIT");
      res.set("Cache-Control", "no-store");
      return res.status(201).json({ id: orderId, status: "pending", total_bif: Number(totalBif) });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.patch("/api/patient/orders/:id/cancel", asyncRoute(async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const order = await client.query(
        "SELECT id, status FROM patient_orders WHERE id = $1 AND patient_id = $2 FOR UPDATE",
        [req.params.id, req.patientUser.id]
      );
      if (!order.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Order not found." });
      }
      if (order.rows[0].status !== "pending") {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Only pending orders can be cancelled." });
      }
      const items = await client.query(
        "SELECT product_id, quantity FROM patient_order_items WHERE order_id = $1",
        [req.params.id]
      );
      for (const item of items.rows) {
        if (item.product_id) {
          await client.query(
            "UPDATE products SET stock_quantity = stock_quantity + $2, updated_at = NOW() WHERE id = $1",
            [item.product_id, item.quantity]
          );
        }
      }
      await client.query(
        "UPDATE patient_orders SET status = 'cancelled', updated_at = NOW() WHERE id = $1",
        [req.params.id]
      );
      await client.query("COMMIT");
      return res.json({ id: req.params.id, status: "cancelled" });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.use("/api/admin", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation);

  app.patch("/api/admin/care-requests/:id/assign-doctor", requireRole("admin"), asyncRoute(async (req, res) => {
    const doctorId = typeof req.body?.doctor_id === "string" ? req.body.doctor_id : "";
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(doctorId)) {
      return res.status(400).json({ error: "Choose a valid doctor account." });
    }
    const doctor = await pool.query("SELECT id FROM staff_users WHERE id = $1 AND role = 'doctor' AND is_active = TRUE", [doctorId]);
    if (!doctor.rowCount) return res.status(404).json({ error: "Active doctor account not found." });
    const result = await pool.query(
      `UPDATE patient_care_requests SET assigned_doctor_id = $2,
         doctor_consultation_status = 'assigned', doctor_scheduled_at = NULL,
         doctor_meeting_url = NULL, doctor_duration_minutes = 30, updated_at = NOW()
       WHERE id = $1 AND doctor_consultation_status IN ('requested', 'assigned', 'contacted', 'scheduled')
       RETURNING id, assigned_doctor_id, doctor_consultation_status, updated_at`,
      [req.params.id, doctorId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Open doctor consultation request not found." });
    return res.json(result.rows[0]);
  }));

  app.get("/api/doctor/consultations", requireStaff, requireRole("doctor"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT requests.id, requests.treatment_location, requests.treated_on,
              requests.doctor_consultation_status AS status, requests.doctor_scheduled_at,
              requests.doctor_duration_minutes, requests.doctor_meeting_url,
              requests.created_at, requests.updated_at, patients.full_name AS patient_name,
              requests.prescription_filename IS NOT NULL AS has_prescription
       FROM patient_care_requests requests
       JOIN patient_users patients ON patients.id = requests.patient_id
       WHERE requests.assigned_doctor_id = $1
       ORDER BY COALESCE(requests.doctor_scheduled_at, requests.updated_at) DESC LIMIT 200`,
      [req.staffUser.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows.map(consultation => ({
      ...consultation,
      doctor_meeting_url: consultation.status === "scheduled" ? doctorCallUrl(consultation.id) : null
    })));
  }));

  app.get("/api/doctor/consultations/:id/call", requireStaff, requireRole("doctor"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id, doctor_consultation_status AS status, doctor_scheduled_at,
              doctor_duration_minutes
       FROM patient_care_requests
       WHERE id = $1 AND assigned_doctor_id = $2 AND doctor_consultation_status = 'scheduled'`,
      [req.params.id, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Booked consultation not found." });
    res.set("Cache-Control", "no-store");
    return res.json({ ...result.rows[0], role: "doctor", call_url: doctorCallUrl(req.params.id), ice_servers: config.rtcIceServers });
  }));

  app.get("/api/doctor/consultations/:id/call/signals", requireStaff, requireRole("doctor"), asyncRoute(async (req, res) => {
    const after = callSignalCursor(req, res);
    if (after === null) return;
    const result = await pool.query(
      `SELECT signals.id::text AS id, signals.signal
       FROM doctor_call_signals signals
       JOIN patient_care_requests requests ON requests.id = signals.care_request_id
       WHERE signals.care_request_id = $1 AND requests.assigned_doctor_id = $2
         AND requests.doctor_consultation_status = 'scheduled'
         AND signals.recipient_role = 'doctor' AND signals.id > $3::bigint
       ORDER BY signals.id LIMIT 100`,
      [req.params.id, req.staffUser.id, after]
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows);
  }));

  app.post("/api/doctor/consultations/:id/call/reset", requireStaff, requireRole("doctor"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `DELETE FROM doctor_call_signals signals
       USING patient_care_requests requests
       WHERE signals.care_request_id = requests.id AND requests.id = $1
         AND requests.assigned_doctor_id = $2 AND requests.doctor_consultation_status = 'scheduled'
       RETURNING signals.id`,
      [req.params.id, req.staffUser.id]
    );
    const appointment = await pool.query(
      `SELECT id FROM patient_care_requests
       WHERE id = $1 AND assigned_doctor_id = $2 AND doctor_consultation_status = 'scheduled'`,
      [req.params.id, req.staffUser.id]
    );
    if (!appointment.rowCount) return res.status(404).json({ error: "Booked consultation not found." });
    res.set("Cache-Control", "no-store");
    return res.json({ cleared_signals: result.rowCount });
  }));

  app.post("/api/doctor/consultations/:id/call/signals", requireStaff, requireRole("doctor"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const validated = validateCallSignal(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const result = await pool.query(
      `INSERT INTO doctor_call_signals (care_request_id, sender_role, recipient_role, signal)
       SELECT requests.id, 'doctor', 'patient', $3::jsonb
       FROM patient_care_requests requests
       WHERE requests.id = $1 AND requests.assigned_doctor_id = $2
         AND requests.doctor_consultation_status = 'scheduled'
       RETURNING id::text AS id`,
      [req.params.id, req.staffUser.id, JSON.stringify(validated.value)]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Booked consultation not found." });
    await pool.query("DELETE FROM doctor_call_signals WHERE created_at < NOW() - INTERVAL '1 day'");
    return res.status(201).json({ id: result.rows[0].id });
  }));

  app.put("/api/doctor/consultations/:id", requireStaff, requireRole("doctor"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const scheduledAt = typeof req.body?.scheduled_at === "string" ? req.body.scheduled_at : "";
    const appointment = Date.parse(scheduledAt);
    const duration = req.body?.duration_minutes === undefined ? 30 : Number(req.body.duration_minutes);
    if (!scheduledAt || !Number.isFinite(appointment) || appointment <= Date.now()) return res.status(400).json({ error: "Choose an appointment time in the future." });
    if (!Number.isInteger(duration) || duration < 15 || duration > 120) return res.status(400).json({ error: "Appointment length must be between 15 and 120 minutes." });
    const meetingUrl = doctorCallUrl(req.params.id);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT id FROM staff_users WHERE id = $1 FOR UPDATE", [req.staffUser.id]);
      const conflict = await client.query(
        `SELECT id FROM patient_care_requests
         WHERE assigned_doctor_id = $1 AND id <> $2 AND doctor_consultation_status = 'scheduled'
           AND tstzrange(doctor_scheduled_at,
                 doctor_scheduled_at + doctor_duration_minutes * INTERVAL '1 minute', '[)') &&
               tstzrange($3::timestamptz, $3::timestamptz + $4 * INTERVAL '1 minute', '[)')
         LIMIT 1`,
        [req.staffUser.id, req.params.id, new Date(appointment).toISOString(), duration]
      );
      if (conflict.rowCount) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "This time overlaps another booked appointment." });
      }
      const result = await client.query(
        `UPDATE patient_care_requests SET doctor_consultation_status = 'scheduled',
           doctor_scheduled_at = $3, doctor_duration_minutes = $4,
           doctor_meeting_url = $5, updated_at = NOW()
         WHERE id = $1 AND assigned_doctor_id = $2
           AND doctor_consultation_status IN ('assigned', 'contacted', 'scheduled')
         RETURNING id, doctor_consultation_status AS status, doctor_scheduled_at,
                   doctor_duration_minutes, doctor_meeting_url, updated_at`,
        [req.params.id, req.staffUser.id, new Date(appointment).toISOString(), duration, meetingUrl]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Assigned consultation not found." });
      }
      await client.query("COMMIT");
      res.set("Cache-Control", "no-store");
      return res.json(result.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.patch("/api/doctor/consultations/:id", requireStaff, requireRole("doctor"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    if (req.body?.status !== "completed") return res.status(400).json({ error: "Doctors can mark a booked consultation as completed." });
    const result = await pool.query(
      `UPDATE patient_care_requests SET doctor_consultation_status = 'completed', updated_at = NOW()
       WHERE id = $1 AND assigned_doctor_id = $2 AND doctor_consultation_status = 'scheduled'
       RETURNING id, doctor_consultation_status AS status, updated_at`,
      [req.params.id, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Booked assigned consultation not found." });
    return res.json(result.rows[0]);
  }));

  app.get("/api/doctor/consultations/:id/messages", requireStaff, requireRole("doctor"), asyncRoute(async (req, res) => {
    const assigned = await pool.query("SELECT id FROM patient_care_requests WHERE id = $1 AND assigned_doctor_id = $2", [req.params.id, req.staffUser.id]);
    if (!assigned.rowCount) return res.status(404).json({ error: "Assigned consultation not found." });
    const result = await pool.query(
      `SELECT messages.id, messages.message, messages.created_at,
              CASE WHEN messages.sender_doctor_id IS NULL THEN 'patient' ELSE 'doctor' END AS sender,
              COALESCE(doctor.username, patients.full_name) AS sender_name
       FROM doctor_consultation_messages messages
       LEFT JOIN staff_users doctor ON doctor.id = messages.sender_doctor_id
       LEFT JOIN patient_users patients ON patients.id = messages.sender_patient_id
       WHERE messages.care_request_id = $1 ORDER BY messages.created_at, messages.id`,
      [req.params.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows);
  }));

  app.post("/api/doctor/consultations/:id/messages", requireStaff, requireRole("doctor"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const validated = validateCareMessage(req.body?.message);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const assigned = await pool.query(
      `SELECT id FROM patient_care_requests WHERE id = $1 AND assigned_doctor_id = $2
       AND doctor_consultation_status <> 'completed'`,
      [req.params.id, req.staffUser.id]
    );
    if (!assigned.rowCount) return res.status(404).json({ error: "Active assigned consultation not found." });
    const result = await pool.query(
      `INSERT INTO doctor_consultation_messages (care_request_id, sender_doctor_id, message)
       VALUES ($1, $2, $3) RETURNING id, message, created_at`,
      [req.params.id, req.staffUser.id, validated.value]
    );
    await pool.query("UPDATE patient_care_requests SET updated_at = NOW() WHERE id = $1", [req.params.id]);
    res.set("Cache-Control", "no-store");
    return res.status(201).json({ ...result.rows[0], sender: "doctor", sender_name: req.staffUser.username });
  }));

  app.get("/api/doctor/consultations/:id/prescription", requireStaff, requireRole("doctor"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT prescription_filename, prescription_mime_type FROM patient_care_requests
       WHERE id = $1 AND assigned_doctor_id = $2 AND prescription_filename IS NOT NULL`,
      [req.params.id, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Prescription not found for this assigned consultation." });
    res.set({ "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff" });
    return res.type(result.rows[0].prescription_mime_type).download(path.join(config.patientCareDirectory, result.rows[0].prescription_filename));
  }));

  app.get("/api/staff/care-requests", requireStaff, requireAnyRole("admin", "pharmacist"), asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT requests.id, requests.patient_id, patients.full_name AS patient_name,
              requests.treatment_location, requests.treated_on, requests.status,
              requests.doctor_consultation_status,
              requests.assigned_doctor_id, doctor.username AS assigned_doctor_name,
              requests.prescription_filename IS NOT NULL AS has_prescription,
              requests.created_at, requests.updated_at
       FROM patient_care_requests requests
       JOIN patient_users patients ON patients.id = requests.patient_id
       LEFT JOIN staff_users doctor ON doctor.id = requests.assigned_doctor_id
       ORDER BY requests.updated_at DESC LIMIT 200`
    );
    res.set("Cache-Control", "no-store");
    return res.json(result.rows);
  }));

  app.get("/api/staff/care-requests/:id/messages", requireStaff, requireAnyRole("admin", "pharmacist"), asyncRoute(async (req, res) => {
    const exists = await pool.query("SELECT id FROM patient_care_requests WHERE id = $1", [req.params.id]);
    if (!exists.rowCount) return res.status(404).json({ error: "Care request not found." });
    const messages = await pool.query(
      `SELECT messages.id, messages.message, messages.created_at,
              CASE WHEN messages.sender_staff_id IS NULL THEN 'patient' ELSE 'staff' END AS sender,
              COALESCE(staff.username, patients.full_name) AS sender_name
       FROM patient_care_messages messages
       LEFT JOIN staff_users staff ON staff.id = messages.sender_staff_id
       LEFT JOIN patient_users patients ON patients.id = messages.sender_patient_id
       WHERE messages.request_id = $1 ORDER BY messages.created_at, messages.id`,
      [req.params.id]
    );
    res.set("Cache-Control", "no-store");
    return res.json(messages.rows);
  }));

  app.post("/api/staff/care-requests/:id/messages", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const validated = validateCareMessage(req.body?.message);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const exists = await pool.query("SELECT id FROM patient_care_requests WHERE id = $1 AND status <> 'closed'", [req.params.id]);
    if (!exists.rowCount) return res.status(404).json({ error: "Open care request not found." });
    const result = await pool.query(
      `INSERT INTO patient_care_messages (request_id, sender_staff_id, message)
       VALUES ($1, $2, $3) RETURNING id, message, created_at`,
      [req.params.id, req.staffUser.id, validated.value]
    );
    await pool.query("UPDATE patient_care_requests SET status = 'in_progress', updated_at = NOW() WHERE id = $1", [req.params.id]);
    res.set("Cache-Control", "no-store");
    return res.status(201).json({ ...result.rows[0], sender: "staff", sender_name: req.staffUser.username });
  }));

  app.patch("/api/staff/care-requests/:id", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation, asyncRoute(async (req, res) => {
    const status = req.body?.status;
    const doctorStatus = req.body?.doctor_consultation_status;
    if (status !== undefined && !["open", "in_progress", "closed"].includes(status)) {
      return res.status(400).json({ error: "Choose a valid care request status." });
    }
    if (doctorStatus !== undefined && !["requested", "contacted"].includes(doctorStatus)) {
      return res.status(400).json({ error: "Only a doctor can schedule or complete the consultation." });
    }
    if (status === undefined && doctorStatus === undefined) return res.status(400).json({ error: "Provide a status update." });
    const result = await pool.query(
      `UPDATE patient_care_requests
       SET status = COALESCE($2, status),
           doctor_consultation_status = COALESCE($3, doctor_consultation_status),
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, status, doctor_consultation_status, updated_at`,
      [req.params.id, status || null, doctorStatus || null]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Care request not found." });
    return res.json(result.rows[0]);
  }));

  app.get("/api/staff/care-requests/:id/prescription", requireStaff, requireAnyRole("admin", "pharmacist"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT prescription_filename, prescription_mime_type FROM patient_care_requests
       WHERE id = $1 AND prescription_filename IS NOT NULL`,
      [req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Prescription not found." });
    res.set({ "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff" });
    return res.type(result.rows[0].prescription_mime_type).download(path.join(config.patientCareDirectory, result.rows[0].prescription_filename));
  }));

  app.use("/api/staff/news", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation);
  app.post("/api/staff/news/preview", asyncRoute(async (req, res) => {
    const validated = validateNewsArticle({ ...req.body, status: "draft", scheduled_at: "" });
    if (validated.error) return res.status(400).json({ error: validated.error });
    res.set("Cache-Control", "no-store");
    return res.json({ body: sanitizeArticleHtml(validated.value.body) });
  }));
  app.get("/api/staff/news", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT articles.id, articles.title, articles.summary, articles.body, articles.video_url, articles.image_url,
              articles.category, articles.status, articles.scheduled_at, articles.views_count,
              articles.author_id, articles.published_at, articles.created_at, articles.updated_at,
              users.username AS author
       FROM news_articles articles LEFT JOIN staff_users users ON users.id = articles.author_id
       ORDER BY COALESCE(articles.published_at, articles.scheduled_at, articles.updated_at) DESC`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.post("/api/staff/news", asyncRoute(async (req, res) => {
    const validated = validateNewsArticle(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const articleId = randomUUID();
    const result = await pool.query(
      `INSERT INTO news_articles
         (id, title, summary, body, video_url, image_url, category, status, scheduled_at, published_at, author_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
         CASE WHEN $8 = 'published' THEN NOW() ELSE NULL END, $10)
       RETURNING id, title, summary, body, video_url, image_url, category, status, scheduled_at, views_count,
                 published_at, created_at, updated_at`,
      [articleId, validated.value.title, validated.value.summary, validated.value.body,
        validated.value.videoUrl, validated.value.imageUrl, validated.value.category, validated.value.status,
        validated.value.scheduledAt, req.staffUser.id]
    );
    const newsletter = validated.value.status === "published" ? await deliverNewsArticle(result.rows[0]) : null;
    return res.status(201).json({ article: result.rows[0], newsletter });
  }));

  app.put("/api/staff/news/:id", asyncRoute(async (req, res) => {
    const validated = validateNewsArticle(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const result = await pool.query(
      `UPDATE news_articles
       SET title = $3, summary = $4, body = $5, video_url = $6, image_url = $7, category = $8,
           status = $9, scheduled_at = $10,
           published_at = CASE
             WHEN $9 = 'published' AND news_articles.status <> 'published' THEN NOW()
             WHEN $9 = 'published' THEN COALESCE(news_articles.published_at, NOW())
             WHEN $9 = 'scheduled' THEN NULL
             ELSE news_articles.published_at
           END,
           updated_at = NOW()
       WHERE id = $1 AND ($2 = 'admin' OR author_id = $11)
       RETURNING id, title, summary, body, video_url, image_url, category, status, scheduled_at,
                 views_count, published_at, created_at, updated_at`,
      [req.params.id, req.staffUser.role, validated.value.title, validated.value.summary,
        validated.value.body, validated.value.videoUrl, validated.value.imageUrl, validated.value.category,
        validated.value.status, validated.value.scheduledAt, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "News article not found or you cannot edit it." });
    const newsletter = validated.value.status === "published" ? await deliverNewsArticle(result.rows[0]) : null;
    return res.json({ article: result.rows[0], newsletter });
  }));

  app.post("/api/staff/news/:id/notify", outboundEmailLimiter, asyncRoute(async (req, res) => {
    if (!emailIsConfigured()) throw emailConfigurationError();
    const result = await pool.query(
      `SELECT id, title, summary, video_url FROM news_articles
       WHERE id = $1 AND status = 'published' AND ($2 = 'admin' OR author_id = $3)`,
      [req.params.id, req.staffUser.role, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "News article not found or you cannot send it." });
    const newsletter = await deliverNewsArticle(result.rows[0]);
    return res.json({ newsletter });
  }));

  app.delete("/api/staff/news/:id", asyncRoute(async (req, res) => {
    const result = await pool.query(
      "DELETE FROM news_articles WHERE id = $1 AND ($2 = 'admin' OR author_id = $3) RETURNING id",
      [req.params.id, req.staffUser.role, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "News article not found or you cannot remove it." });
    return res.status(204).end();
  }));

  app.use("/api/staff/content/images", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation);
  app.post("/api/staff/content/images", upload.single("image"), asyncRoute(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Choose an image to upload." });
    const image = await writeImage(req.file.buffer);
    return res.status(201).json({ image_url: image.url });
  }));

  app.use("/api/staff/videos", requireStaff, requireAnyRole("admin", "pharmacist"), requireCsrfForMutation);
  app.get("/api/staff/videos", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT videos.id, videos.title, videos.description, videos.category, videos.source_type,
              videos.video_url, videos.thumbnail_url, videos.status, videos.scheduled_at,
              videos.published_at, videos.views_count, videos.author_id, videos.created_at,
              videos.updated_at, users.username AS author
       FROM videos LEFT JOIN staff_users users ON users.id = videos.author_id
       ORDER BY COALESCE(videos.published_at, videos.scheduled_at, videos.updated_at) DESC`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.post("/api/staff/videos/upload", videoUpload.single("video"), asyncRoute(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Choose an MP4 or WebM video to upload." });
    return res.status(201).json({ video_url: await writeVideo(req.file) });
  }));

  app.post("/api/staff/videos", asyncRoute(async (req, res) => {
    const validated = validateVideo(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (validated.value.sourceType === "upload") {
      await fs.access(path.join(config.videoUploadDirectory, path.basename(validated.value.videoUrl)));
    }
    const videoId = randomUUID();
    const result = await pool.query(
      `INSERT INTO videos
         (id, title, description, category, source_type, video_url, thumbnail_url,
          status, scheduled_at, published_at, author_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
          CASE WHEN $8 = 'published' THEN NOW() ELSE NULL END, $10)
       RETURNING *`,
      [videoId, validated.value.title, validated.value.description, validated.value.category,
        validated.value.sourceType, validated.value.videoUrl, validated.value.thumbnailUrl,
        validated.value.status, validated.value.scheduledAt, req.staffUser.id]
    );
    return res.status(201).json(result.rows[0]);
  }));

  app.put("/api/staff/videos/:id", asyncRoute(async (req, res) => {
    const validated = validateVideo(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (validated.value.sourceType === "upload") {
      await fs.access(path.join(config.videoUploadDirectory, path.basename(validated.value.videoUrl)));
    }
    const result = await pool.query(
      `UPDATE videos SET title = $3, description = $4, category = $5, source_type = $6,
         video_url = $7, thumbnail_url = $8, status = $9, scheduled_at = $10,
         published_at = CASE
           WHEN $9 = 'published' AND videos.status <> 'published' THEN NOW()
           WHEN $9 = 'published' THEN COALESCE(videos.published_at, NOW())
           WHEN $9 = 'scheduled' THEN NULL
           ELSE videos.published_at
         END, updated_at = NOW()
       WHERE id = $1 AND ($2 = 'admin' OR author_id = $11)
       RETURNING *`,
      [req.params.id, req.staffUser.role, validated.value.title, validated.value.description,
        validated.value.category, validated.value.sourceType, validated.value.videoUrl,
        validated.value.thumbnailUrl, validated.value.status, validated.value.scheduledAt,
        req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Video not found or you cannot edit it." });
    return res.json(result.rows[0]);
  }));

  app.delete("/api/staff/videos/:id", asyncRoute(async (req, res) => {
    const result = await pool.query(
      `DELETE FROM videos WHERE id = $1 AND ($2 = 'admin' OR author_id = $3)
       RETURNING source_type, video_url`,
      [req.params.id, req.staffUser.role, req.staffUser.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Video not found or you cannot delete it." });
    if (result.rows[0].source_type === "upload") await removeVideo(result.rows[0].video_url);
    return res.status(204).end();
  }));

  app.get("/api/admin/staff", requireRole("admin"), asyncRoute(async (_req, res) => {
    const result = await pool.query(
      "SELECT id, username, role, is_active, created_at FROM staff_users ORDER BY created_at DESC"
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.get("/api/admin/staff/invitations", requireRole("admin"), asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT id, email, role, expires_at, created_at FROM staff_invitations
       WHERE accepted_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.delete("/api/admin/staff/invitations/:id", requireRole("admin"), asyncRoute(async (req, res) => {
    const result = await pool.query(
      "DELETE FROM staff_invitations WHERE id = $1 AND accepted_at IS NULL RETURNING id",
      [req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Pending invitation not found." });
    return res.status(204).end();
  }));

  app.post("/api/admin/staff/invitations", requireRole("admin"), outboundEmailLimiter, asyncRoute(async (req, res) => {
    const validated = validateStaffInvitation(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (!emailIsConfigured()) throw emailConfigurationError();
    const existing = await pool.query("SELECT 1 FROM staff_users WHERE username = $1", [validated.value.email]);
    if (existing.rowCount) return res.status(409).json({ error: "A staff account already exists for that email." });

    const token = randomBytes(32).toString("base64url");
    const invitationId = randomUUID();
    await pool.query("DELETE FROM staff_invitations WHERE email = $1 AND accepted_at IS NULL", [validated.value.email]);
    await pool.query(
      `INSERT INTO staff_invitations (id, email, role, token_hash, invited_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '48 hours')`,
      [invitationId, validated.value.email, validated.value.role, hashToken(token), req.staffUser.id]
    );
    const invitationUrl = `${config.publicSiteUrl}/staff-invite?token=${encodeURIComponent(token)}`;
    try {
      await sendEmailBatch([{
        to: validated.value.email,
        subject: "Ubutumire bwo gukorana na UBUZIMA PHARMA",
        html: `<p>Waratumiriwe gukorana na UBUZIMA PHARMA nk'${validated.value.role === "admin" ? "umuyobozi" : validated.value.role === "doctor" ? "muganga" : "umufarumasiye"}.</p><p><a href="${invitationUrl}">Emeza ubutumire wongere ijambobanga ryawe</a></p><p>Iyi link imara amasaha 48. Nimba utazi ibijanye n'ubu butumire, wirengagize ubu butumwa.</p>`,
        text: `Waratumiriwe gukorana na UBUZIMA PHARMA. Emeza ubutumire ushireho ijambobanga ryawe: ${invitationUrl}\nIyi link imara amasaha 48.`
      }]);
    } catch (error) {
      await pool.query("DELETE FROM staff_invitations WHERE id = $1", [invitationId]);
      throw error;
    }
    return res.status(201).json({ id: invitationId, email: validated.value.email, role: validated.value.role, expires_in_hours: 48 });
  }));

  app.patch("/api/admin/staff/:id/active", requireRole("admin"), asyncRoute(async (req, res) => {
    if (typeof req.body?.is_active !== "boolean") {
      return res.status(400).json({ error: "Account status must be a boolean." });
    }
    if (req.params.id === req.staffUser.id && !req.body.is_active) {
      return res.status(400).json({ error: "You cannot deactivate your own account." });
    }
    const result = await pool.query(
      `UPDATE staff_users SET is_active = $2 WHERE id = $1
       RETURNING id, username, role, is_active, created_at`,
      [req.params.id, req.body.is_active]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Staff account not found." });
    return res.json(result.rows[0]);
  }));

  app.get("/api/admin/patients", requireRole("admin"), asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT patients.id, patients.email, patients.full_name, patients.phone,
              patients.is_active, patients.created_at, COUNT(orders.id)::INTEGER AS order_count
       FROM patient_users patients
       LEFT JOIN patient_orders orders ON orders.patient_id = patients.id
       GROUP BY patients.id ORDER BY patients.created_at DESC`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.patch("/api/admin/patients/:id/active", requireRole("admin"), asyncRoute(async (req, res) => {
    if (typeof req.body?.is_active !== "boolean") {
      return res.status(400).json({ error: "Account status must be a boolean." });
    }
    const result = await pool.query(
      `UPDATE patient_users SET is_active = $2 WHERE id = $1
       RETURNING id, email, full_name, phone, is_active, created_at`,
      [req.params.id, req.body.is_active]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Patient account not found." });
    return res.json(result.rows[0]);
  }));

  app.get("/api/admin/orders", requireRole("admin"), asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT orders.id, orders.patient_id, patients.full_name, patients.email, patients.phone,
              orders.status, orders.total_bif, orders.created_at, orders.updated_at
       FROM patient_orders orders
       JOIN patient_users patients ON patients.id = orders.patient_id
       ORDER BY orders.created_at DESC LIMIT 500`
    );
    const details = await fetchOrderDetails(result.rows.map(order => order.id));
    const itemsByOrder = new Map();
    for (const item of details.rows) {
      const items = itemsByOrder.get(item.order_id) || [];
      items.push({
        product_id: item.product_id,
        product_name: item.product_name,
        quantity: item.quantity,
        unit_price_bif: Number(item.unit_price_bif)
      });
      itemsByOrder.set(item.order_id, items);
    }
    res.set("Cache-Control", "no-store");
    res.json(result.rows.map(order => ({
      ...order,
      total_bif: Number(order.total_bif),
      items: itemsByOrder.get(order.id) || []
    })));
  }));

  app.patch("/api/admin/orders/:id/status", requireRole("admin"), asyncRoute(async (req, res) => {
    const nextStatus = req.body?.status;
    if (!["confirmed", "ready", "completed", "cancelled"].includes(nextStatus)) {
      return res.status(400).json({ error: "Choose a valid order status." });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const order = await client.query(
        "SELECT id, status FROM patient_orders WHERE id = $1 FOR UPDATE",
        [req.params.id]
      );
      if (!order.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Order not found." });
      }
      const currentStatus = order.rows[0].status;
      const allowedTransitions = {
        pending: ["confirmed", "cancelled"],
        confirmed: ["ready", "cancelled"],
        ready: ["completed"],
        completed: [],
        cancelled: []
      };
      if (!allowedTransitions[currentStatus].includes(nextStatus)) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "That order status transition is not allowed." });
      }
      if (nextStatus === "cancelled") {
        const items = await client.query(
          "SELECT product_id, quantity FROM patient_order_items WHERE order_id = $1",
          [req.params.id]
        );
        for (const item of items.rows) {
          if (item.product_id) {
            await client.query(
              "UPDATE products SET stock_quantity = stock_quantity + $2, updated_at = NOW() WHERE id = $1",
              [item.product_id, item.quantity]
            );
          }
        }
      }
      await client.query(
        "UPDATE patient_orders SET status = $2, updated_at = NOW() WHERE id = $1",
        [req.params.id, nextStatus]
      );
      await client.query("COMMIT");
      return res.json({ id: req.params.id, status: nextStatus });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/api/admin/products", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
              pack_size, manufacturer, directions_for_use, warnings, storage_instructions,
              indications, price_bif, stock_quantity, image_url, is_available, created_at, updated_at
       FROM products ORDER BY updated_at DESC`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows.map(publicProduct));
  }));

  app.post("/api/admin/products", upload.single("image"), asyncRoute(async (req, res) => {
    const validated = validateProduct(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    if (!req.file && !validated.value.imageUrl) {
      return res.status(400).json({ error: "Upload a product image or provide an HTTPS image URL." });
    }

    const imageUrl = req.file ? (await writeImage(req.file.buffer)).url : validated.value.imageUrl;
    const id = randomUUID();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `INSERT INTO products (
           id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
           pack_size, manufacturer, directions_for_use, indications, warnings, storage_instructions,
           price_bif, stock_quantity, image_url, is_available
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
         RETURNING id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
                   pack_size, manufacturer, directions_for_use, indications, warnings, storage_instructions,
                   price_bif, stock_quantity, image_url, is_available, created_at, updated_at`,
        [
          id, validated.value.name, validated.value.category, validated.value.description,
          validated.value.generic_name, validated.value.active_ingredient, validated.value.strength,
          validated.value.dosage_form, validated.value.pack_size, validated.value.manufacturer,
          validated.value.directions_for_use, validated.value.indications, validated.value.warnings, validated.value.storage_instructions,
          validated.value.priceBif, validated.value.stockQuantity, imageUrl, validated.value.isAvailable
        ]
      );
      await recordAudit(client, req.session.staffId, "product.created", id, { name: validated.value.name });
      await client.query("COMMIT");
      return res.status(201).json(publicProduct(result.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.put("/api/admin/products/:id", upload.single("image"), asyncRoute(async (req, res) => {
    const validated = validateProduct(req.body);
    if (validated.error) return res.status(400).json({ error: validated.error });
    const client = await pool.connect();
    let image;
    try {
      await client.query("BEGIN");
      const current = await client.query("SELECT image_url FROM products WHERE id = $1 FOR UPDATE", [req.params.id]);
      if (!current.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Product not found." });
      }
      if (req.file) image = await writeImage(req.file.buffer);
      const imageUrl = image?.url || validated.value.imageUrl || current.rows[0].image_url;
      const result = await client.query(
        `UPDATE products SET name = $2, category = $3, description = $4,
         generic_name = $5, active_ingredient = $6, strength = $7, dosage_form = $8,
         pack_size = $9, manufacturer = $10, directions_for_use = $11, indications = $12,
         warnings = $13, storage_instructions = $14, price_bif = $15, stock_quantity = $16,
         image_url = $17, is_available = $18, updated_at = NOW()
         WHERE id = $1
         RETURNING id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
                   pack_size, manufacturer, directions_for_use, indications, warnings, storage_instructions,
                   price_bif, stock_quantity, image_url, is_available, created_at, updated_at`,
        [
          req.params.id, validated.value.name, validated.value.category, validated.value.description,
          validated.value.generic_name, validated.value.active_ingredient, validated.value.strength,
          validated.value.dosage_form, validated.value.pack_size, validated.value.manufacturer,
          validated.value.directions_for_use, validated.value.indications, validated.value.warnings, validated.value.storage_instructions,
          validated.value.priceBif, validated.value.stockQuantity, imageUrl, validated.value.isAvailable
        ]
      );
      await recordAudit(client, req.session.staffId, "product.updated", req.params.id, { name: validated.value.name });
      await client.query("COMMIT");
      return res.json(publicProduct(result.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.patch("/api/admin/products/:id/availability", asyncRoute(async (req, res) => {
    if (typeof req.body?.is_available !== "boolean") {
      return res.status(400).json({ error: "Availability must be a boolean." });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `UPDATE products SET is_available = $2, updated_at = NOW() WHERE id = $1
         RETURNING id, name, category, description, generic_name, active_ingredient, strength, dosage_form,
                   pack_size, manufacturer, directions_for_use, indications, warnings, storage_instructions,
                   price_bif, stock_quantity, image_url, is_available, created_at, updated_at`,
        [req.params.id, req.body.is_available]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Product not found." });
      }
      await recordAudit(client, req.session.staffId, req.body.is_available ? "product.unhidden" : "product.hidden", req.params.id);
      await client.query("COMMIT");
      return res.json(publicProduct(result.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.delete("/api/admin/products/:id", asyncRoute(async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query("DELETE FROM products WHERE id = $1 RETURNING image_url, name", [req.params.id]);
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Product not found." });
      }
      await recordAudit(client, req.session.staffId, "product.deleted", req.params.id, { name: result.rows[0].name });
      await client.query("COMMIT");
      return res.status(204).end();
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/api/admin/audit-logs", asyncRoute(async (_req, res) => {
    const result = await pool.query(
      `SELECT logs.id, users.username, logs.action, logs.product_id, logs.details, logs.created_at
       FROM audit_logs logs LEFT JOIN staff_users users ON users.id = logs.staff_user_id
       ORDER BY logs.created_at DESC LIMIT 100`
    );
    res.set("Cache-Control", "no-store");
    res.json(result.rows);
  }));

  app.use((_req, res) => res.status(404).json({ error: "Not found." }));
  app.use((error, _req, res, _next) => {
    if (error instanceof multer.MulterError) {
      const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      const uploadLabel = error.field === "video" ? "Video" : error.field === "prescription" ? "Prescription" : "Image";
      return res.status(status).json({ error: status === 413 ? `${uploadLabel} exceeds the upload size limit.` : `Invalid ${uploadLabel.toLowerCase()} upload.` });
    }
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error("API request failed.", error);
    return res.status(status).json({ error: status >= 500 ? "The request could not be completed." : error.message });
  });

  return app;
}
