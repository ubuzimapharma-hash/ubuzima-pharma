import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { config } from "./config.js";

const { Pool } = pg;

export const pool = new Pool({ connectionString: config.databaseUrl });
pool.on("error", error => {
  console.error("Unexpected PostgreSQL pool error.", error);
});

export async function initializeDatabase() {
  const schemaPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../db/schema.sql");
  const schema = await fs.readFile(schemaPath, "utf8");
  await pool.query(schema);
}
