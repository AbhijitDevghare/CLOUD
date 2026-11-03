require('dotenv').config();
const { initDb, getDbMode } = require('./db');

async function runMigrations() {
  try {
    await initDb();
    console.log(`[Database Migration] Successfully initialized schema and compliance seeds (Mode: ${getDbMode()})`);
    process.exit(0);
  } catch (err) {
    console.error('[Database Migration] Failed:', err.message);
    process.exit(1);
  }
}

runMigrations();
