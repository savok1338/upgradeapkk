import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const dataDir = path.join(__dirname, 'data')

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true })
}

const dbPath = path.join(dataDir, 'upgrader.db')
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
`)

// Ensure account authentication columns exist for legacy DB migrations
try { db.exec(`ALTER TABLE players ADD COLUMN username TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN password_hash TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN auth_token TEXT`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN quests_json TEXT DEFAULT '[]'`) } catch {}
try { db.exec(`ALTER TABLE players ADD COLUMN quest_stats_json TEXT DEFAULT '{}'`) } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_players_username ON players(username)`) } catch {}

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
