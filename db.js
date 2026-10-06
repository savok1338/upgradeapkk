import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { restoreFromBackup, startBackupScheduler } from './backup.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
// DATA_DIR lets the DB live on a mounted persistent disk (e.g. Render Disks: DATA_DIR=/data)
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data')

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true })
}

const dbPath = path.join(dataDir, 'upgrader.db')

// Render free tier has no persistent disk — restore the DB file from the
// GitHub backup before opening the connection (no-op without GH_BACKUP_TOKEN)
if (process.env.GH_BACKUP_TOKEN) {
  try {
    await restoreFromBackup(dbPath)
  } catch (e) {
    console.error('[backup] restore failed, starting with local DB:', e?.message || e)
  }
}

export const db = new DatabaseSync(dbPath)

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS players (
    id TEXT PRIMARY KEY,
    nickname TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 750000,
    level INTEGER NOT NULL DEFAULT 1,
    xp INTEGER NOT NULL DEFAULT 0,
    upgrades_count INTEGER NOT NULL DEFAULT 0,
    won_count INTEGER NOT NULL DEFAULT 0,
    biggest_win INTEGER NOT NULL DEFAULT 0,
    inventory_json TEXT NOT NULL DEFAULT '[]',
    last_active INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    banned INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS promocodes (
    code TEXT PRIMARY KEY,
    amount INTEGER NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 0,
    used_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS promocode_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    player_id TEXT NOT NULL,
    redeemed_at INTEGER NOT NULL,
    UNIQUE(code, player_id)
  );

  CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT,
    timestamp INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL DEFAULT 'global',
    sender_id TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    edited_at INTEGER,
    deleted_at INTEGER,
    FOREIGN KEY(sender_id) REFERENCES players(id)
  );

  CREATE TABLE IF NOT EXISTS wallet_transfers (
    id TEXT PRIMARY KEY,
    from_player_id TEXT NOT NULL,
    to_player_id TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK(amount > 0),
    status TEXT NOT NULL DEFAULT 'completed',
    idempotency_key TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY(from_player_id) REFERENCES players(id),
    FOREIGN KEY(to_player_id) REFERENCES players(id)
  );

  CREATE TABLE IF NOT EXISTS wallet_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id TEXT NOT NULL,
    transfer_id TEXT,
    delta INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(player_id) REFERENCES players(id)
  );
`)

// Ensure account authentication columns exist for legacy DB migrations
try { db.exec(`ALTER TABLE players ADD COLUMN username TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN password_hash TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN auth_token TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN quests_json TEXT DEFAULT '[]'`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN quest_stats_json TEXT DEFAULT '{}'`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN pending_bonus INTEGER DEFAULT 0`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN pending_inventory_json TEXT`) } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_players_username ON players(username)`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN economy_reset_at INTEGER`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN profile_visibility TEXT NOT NULL DEFAULT 'public'`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN bio TEXT NOT NULL DEFAULT ''`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN avatar_url TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN show_inventory INTEGER NOT NULL DEFAULT 0`) } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_players_last_active ON players(last_active)`) } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_chat_channel_created ON chat_messages(channel, created_at)`) } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_wallet_from ON wallet_transfers(from_player_id, created_at)`) } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_wallet_to ON wallet_transfers(to_player_id, created_at)`) } catch {}

export function getAppConfig(key, defaultValue = '') {
  try {
    const row = db.prepare('SELECT value FROM app_config WHERE key = ?').get(key)
    return row ? row.value : defaultValue
  } catch {
    return defaultValue
  }
}

export function setAppConfig(key, value) {
  try {
    db.prepare('INSERT INTO app_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value))
  } catch (e) {
    console.error('Failed to set app_config', e)
  }
}

// Seed default version control config
const defaultConfigs = [
  { key: 'min_version_code', value: '33' },
  { key: 'latest_version_name', value: '3.3' },
  { key: 'telegram_channel', value: '@upgradermobile' },
  { key: 'telegram_url', value: 'https://t.me/upgradermobile' },
  { key: 'update_message', value: 'Вышла новая версия CS2 Upgrader! Скачайте обновление в нашем официальном Telegram канале @upgradermobile.' },
  { key: 'force_update_enabled', value: '1' },
  // Economy reset marker: clients wipe local+cloud progress once when they see
  // a value different from their acked one (bump it via admin to reset everyone)
  { key: 'econ_reset_at', value: String(Date.now()) },
  { key: 'admin_secret', value: process.env.ADMIN_SECRET || 'savokadm8' }
]

for (const conf of defaultConfigs) {
  try {
    db.prepare('INSERT OR IGNORE INTO app_config (key, value) VALUES (?, ?)').run(conf.key, conf.value)
  } catch {}
}

// Seed default starter promocodes if none exist
const countRow = db.prepare('SELECT COUNT(*) as cnt FROM promocodes').get()
if (countRow.cnt === 0) {
  const seedCodes = [
    { code: 'START', amount: 250000, max_uses: 0 },      // 2 500 ₽
    { code: 'LUCKY', amount: 350000, max_uses: 0 },      // 3 500 ₽
    { code: 'CS2PRO', amount: 500000, max_uses: 500 },   // 5 000 ₽
    { code: 'PHANTOM', amount: 750000, max_uses: 100 }   // 7 500 ₽
  ]
  const insertStmt = db.prepare('INSERT INTO promocodes (code, amount, max_uses, used_count, created_at) VALUES (?, ?, ?, 0, ?)')
  const now = Date.now()
  for (const s of seedCodes) {
    insertStmt.run(s.code, s.amount, s.max_uses, now)
  }
}

// Periodic DB snapshots to GitHub + final snapshot on SIGTERM (Render deploys)
startBackupScheduler(db)
