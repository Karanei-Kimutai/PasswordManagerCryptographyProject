/**
 * @file index.js
 *
 * Server entry point: loads configuration, opens the database and listens.
 */

import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { openDatabase } from "./database.js";

const config = loadConfig();
const database = openDatabase(config.databasePath);
const app = createApp({ database, config });

app.listen(config.port, () => {
  console.log(`Tessera API listening on http://localhost:${config.port}`);
  if (!config.isProduction) {
    console.log("Development mode: open the Vite dev server (http://localhost:5173), not this port.");
  }
});
