import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sameSite = process.env.COOKIE_SAME_SITE || "lax";
const allowedSameSites = new Set(["lax", "strict", "none"]);
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 5 * 1024 * 1024);
const maxVideoUploadBytes = Number(process.env.MAX_VIDEO_UPLOAD_BYTES || 104857600);
const port = Number(process.env.PORT || 4000);
let rtcIceServers;
try {
  rtcIceServers = process.env.RTC_ICE_SERVERS
    ? JSON.parse(process.env.RTC_ICE_SERVERS)
    : [{ urls: "stun:stun.l.google.com:19302" }];
} catch {
  throw new Error("RTC_ICE_SERVERS must be valid JSON containing WebRTC ICE server entries.");
}
if (!Array.isArray(rtcIceServers) || rtcIceServers.length < 1 || rtcIceServers.some(server => !server || typeof server !== "object" || !(typeof server.urls === "string" || Array.isArray(server.urls)))) {
  throw new Error("RTC_ICE_SERVERS must be a non-empty array of valid WebRTC ICE server entries.");
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set.");
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 characters.");
}
if (!allowedSameSites.has(sameSite)) {
  throw new Error("COOKIE_SAME_SITE must be lax, strict, or none.");
}
if (!Number.isSafeInteger(maxUploadBytes) || maxUploadBytes < 1 || maxUploadBytes > 10 * 1024 * 1024) {
  throw new Error("MAX_UPLOAD_BYTES must be an integer between 1 and 10485760.");
}
if (!Number.isSafeInteger(maxVideoUploadBytes) || maxVideoUploadBytes < 1 || maxVideoUploadBytes > 524288000) {
  throw new Error("MAX_VIDEO_UPLOAD_BYTES must be an integer between 1 and 524288000.");
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}
if (sameSite === "none" && process.env.NODE_ENV !== "production") {
  throw new Error("COOKIE_SAME_SITE=none requires NODE_ENV=production and HTTPS.");
}

export const config = {
  databaseUrl: process.env.DATABASE_URL,
  isProduction: process.env.NODE_ENV === "production",
  port,
  rtcIceServers,
  sessionSecret: process.env.SESSION_SECRET,
  sameSite,
  trustProxy: process.env.TRUST_PROXY === "1",
  maxUploadBytes,
  maxVideoUploadBytes,
  uploadDirectory: path.resolve(root, process.env.UPLOAD_DIR || "uploads"),
  patientCareDirectory: path.resolve(root, process.env.PATIENT_CARE_DIR || "private-uploads", "patient-care"),
  videoUploadDirectory: path.resolve(root, process.env.UPLOAD_DIR || "uploads", "videos"),
  smtpHost: process.env.SMTP_HOST || "",
  smtpPort: Number(process.env.SMTP_PORT || 587),
  smtpSecure: process.env.SMTP_SECURE === "true",
  smtpUser: process.env.SMTP_USER || "",
  smtpPassword: process.env.SMTP_PASSWORD || "",
  mailFrom: process.env.MAIL_FROM || "",
  resendApiKey: process.env.RESEND_API_KEY || "",
  emailFrom: process.env.EMAIL_FROM || "",
  emailReplyTo: process.env.EMAIL_REPLY_TO || "ubuzimapharma@gmail.com",
  publicSiteUrl: (process.env.PUBLIC_SITE_URL || "http://localhost:3000").replace(/\/+$/, ""),
  corsOrigins: new Set(
    (process.env.CORS_ORIGINS || "http://localhost:3000")
      .split(",")
      .map(origin => origin.trim())
      .filter(Boolean)
  )
};
