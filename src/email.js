import { config } from "./config.js";
import nodemailer from "nodemailer";

let smtpTransporter;

function smtpIsConfigured() {
  return Boolean(
    config.smtpHost &&
    Number.isInteger(config.smtpPort) &&
    config.smtpPort > 0 &&
    config.smtpPort <= 65535 &&
    config.smtpUser &&
    config.smtpPassword &&
    config.mailFrom
  );
}

export function emailIsConfigured() {
  return smtpIsConfigured() || Boolean(config.resendApiKey && config.emailFrom);
}

export async function sendEmailBatch(messages) {
  if (!emailIsConfigured()) {
    throw Object.assign(
      new Error("Email is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and MAIL_FROM, or configure Resend."),
      { status: 503 }
    );
  }
  if (!messages.length) return;
  if (messages.length > 100) throw new Error("Email batches are limited to 100 messages.");

  if (smtpIsConfigured()) {
    smtpTransporter ||= nodemailer.createTransport({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpSecure,
      requireTLS: !config.smtpSecure,
      auth: {
        user: config.smtpUser,
        pass: config.smtpPassword
      }
    });

    for (const message of messages) {
      await smtpTransporter.sendMail({
        from: config.mailFrom,
        replyTo: config.emailReplyTo,
        to: message.to,
        subject: message.subject,
        html: message.html,
        text: message.text
      });
    }
    return;
  }

  const response = await fetch("https://api.resend.com/emails/batch", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(messages.map(message => ({
      from: config.emailFrom,
      reply_to: config.emailReplyTo,
      to: [message.to],
      subject: message.subject,
      html: message.html,
      text: message.text
    })))
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.message || "Resend could not deliver the email batch.");
    error.status = response.status === 429 ? 503 : 502;
    throw error;
  }
}
