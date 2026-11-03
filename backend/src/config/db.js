const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hashPassword } = require('../utils/cryptoAuth');
const { EmbeddedPostgresEngine } = require('./embeddedSqlStore');

let PgPool = null;
try {
  PgPool = require('pg').Pool;
} catch {
  PgPool = null;
}

let pool = null;
let dbMode = 'POSTGRESQL';
let initPromise = null;

/**
 * Seeds default RBAC accounts (Admin, Security Analyst, Compliance Auditor) and
 * baseline safelist entries if they do not exist yet.
 */
async function seedDefaultUsersAndBaselineData(activePool) {
  const orgId = '11111111-1111-1111-1111-111111111111';

  await activePool.query(
    `INSERT INTO organizations (id, name, slug, subscription_tier)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (slug) DO NOTHING`,
    [orgId, 'AegisCloud Enterprise Security', 'aegiscloud-sec', 'ENTERPRISE']
  );

  // Ensure compliance controls are seeded
  await activePool.query(`INSERT INTO compliance_controls DEFAULT VALUES`);

  const existingUsers = await activePool.query(
    'SELECT COUNT(*)::int AS count FROM users WHERE organization_id = $1',
    [orgId]
  );
  if (existingUsers.rows[0].count === 0) {
    const adminHash = await hashPassword('Admin@12345!', 10);
    const analystHash = await hashPassword('Analyst@12345!', 10);
    const auditorHash = await hashPassword('Auditor@12345!', 10);

    await activePool.query(
      `INSERT INTO users (id, organization_id, email, password_hash, full_name, role, is_active, mfa_enabled)
       VALUES
       ($1, $2, 'admin@aegiscloud.io', $3, 'Elena Vance (Platform Admin)', 'ADMIN', true, true),
       ($4, $2, 'analyst@aegiscloud.io', $5, 'Marcus Chen (Senior SOC Analyst)', 'ANALYST', true, false),
       ($6, $2, 'auditor@aegiscloud.io', $7, 'Priya Nair (Compliance & GRC Auditor)', 'AUDITOR', true, false)`,
      [
        '22222222-2222-2222-2222-222222222221',
        orgId,
        adminHash,
        '22222222-2222-2222-2222-222222222222',
        analystHash,
        '22222222-2222-2222-2222-222222222223',
        auditorHash
      ]
    );

    await activePool.query(
      `INSERT INTO ip_safelist (organization_id, ip_cidr, label, created_by)
       VALUES
       ($1, '127.0.0.1/32', 'Local Loopback Interface', '22222222-2222-2222-2222-222222222221'),
       ($1, '10.0.0.0/8', 'Internal VPC Private Network', '22222222-2222-2222-2222-222222222221'),
       ($1, '198.51.100.10/32', 'Corporate VPN Gateway Egress', '22222222-2222-2222-2222-222222222221')`,
      [orgId]
    );
  }
}

async function createEmbeddedPostgresPool() {
  try {
    const { newDb } = require('pg-mem');
    const db = newDb();

    db.public.registerFunction({
      name: 'uuid_generate_v4',
      returns: 'uuid',
      implementation: () => crypto.randomUUID(),
      impure: true
    });

    db.public.registerFunction({
      name: 'now',
      returns: 'timestamptz',
      implementation: () => new Date().toISOString(),
      impure: true
    });

    const PgMemPool = db.adapters.createPg().Pool;
    const memPool = new PgMemPool();

    const schemaPath = path.resolve(__dirname, '../../../database/migrations/001_initial_schema.sql');
    const seedPath = path.resolve(__dirname, '../../../database/seeds/001_compliance_controls.sql');

    const schemaSql = fs
      .readFileSync(schemaPath, 'utf8')
      .replace(/CREATE EXTENSION IF NOT EXISTS "uuid-ossp";/gi, '');

    await memPool.query(schemaSql);
    await memPool.query(fs.readFileSync(seedPath, 'utf8'));
    await seedDefaultUsersAndBaselineData(memPool);

    dbMode = 'EMBEDDED_PG_MEM';
    return memPool;
  } catch {
    const engine = new EmbeddedPostgresEngine();
    await seedDefaultUsersAndBaselineData(engine);
    dbMode = 'EMBEDDED_POSTGRES_ENGINE';
    return engine;
  }
}

async function initDb() {
  if (pool) return pool;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    if (process.env.FORCE_PG_MEM === 'true' || !PgPool) {
      pool = await createEmbeddedPostgresPool();
      return pool;
    }

    const candidatePool = new PgPool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://secadmin:secpassword@localhost:5432/cloud_sec_platform',
      connectionTimeoutMillis: 1500
    });

    try {
      await candidatePool.query('SELECT 1');
      const schemaPath = path.resolve(__dirname, '../../../database/migrations/001_initial_schema.sql');
      const seedPath = path.resolve(__dirname, '../../../database/seeds/001_compliance_controls.sql');

      await candidatePool.query(fs.readFileSync(schemaPath, 'utf8'));
      await candidatePool.query(fs.readFileSync(seedPath, 'utf8'));
      await seedDefaultUsersAndBaselineData(candidatePool);

      pool = candidatePool;
      dbMode = 'POSTGRESQL';
      return pool;
    } catch {
      try {
        await candidatePool.end();
      } catch {
        // ignore
      }
      pool = await createEmbeddedPostgresPool();
      return pool;
    }
  })();

  return initPromise;
}

async function query(text, params = []) {
  const activePool = await initDb();
  return activePool.query(text, params);
}

function getDbMode() {
  return dbMode;
}

module.exports = {
  initDb,
  query,
  getDbMode,
  DEFAULT_ORG_ID: '11111111-1111-1111-1111-111111111111'
};
