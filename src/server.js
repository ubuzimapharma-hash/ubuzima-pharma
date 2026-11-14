import "dotenv/config";
import fs from "node:fs/promises";
import { config } from "./config.js";
import { initializeDatabase, pool } from "./db.js";
import { createApp } from "./app.js";

async function start() {
  await fs.mkdir(config.uploadDirectory, { recursive: true });
  await fs.mkdir(config.videoUploadDirectory, { recursive: true });
  await initializeDatabase();
  await pool.query("SELECT 1");

  const app = createApp();
  const server = app.listen(config.port, () => {
    console.log(`UBUZIMA PHARMA API listening on port ${config.port}.`);
  });

  const shutdown = signal => {
    console.log(`${signal} received; closing the API.`);
    server.close(async error => {
      if (error) {
        console.error("Could not close the HTTP server cleanly.", error);
        process.exitCode = 1;
      }
      await pool.end();
    });
  };

  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}

start().catch(async error => {
  console.error("API startup failed.", error);
  await pool.end();
  process.exitCode = 1;
});
