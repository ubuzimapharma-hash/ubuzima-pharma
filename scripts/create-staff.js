import "dotenv/config";
import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { initializeDatabase, pool } from "../src/db.js";

const email = (process.env.STAFF_EMAIL || "ubuzimapharma@gmail.com").trim().toLowerCase();
const password = process.env.STAFF_PASSWORD;
const role = process.env.STAFF_ROLE || "admin";

const validationErrors = [];
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
  validationErrors.push("STAFF_EMAIL must be a valid email address.");
}
if (!password || password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
  validationErrors.push("STAFF_PASSWORD must be at least 12 characters and no more than 72 UTF-8 bytes.");
}
if (!["admin", "pharmacist"].includes(role)) {
  validationErrors.push("STAFF_ROLE must be admin or pharmacist.");
}

if (validationErrors.length) {
  console.error(`Cannot provision staff account:\n- ${validationErrors.join("\n- ")}`);
  process.exitCode = 1;
} else {
  try {
    await initializeDatabase();
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO staff_users (id, username, password_hash, role)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, is_active = TRUE`,
      [randomUUID(), email, passwordHash, role]
    );
    console.log(`Staff account "${email}" created or updated with role "${role}".`);
  } catch (error) {
    console.error("Could not create the staff account.", error);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
