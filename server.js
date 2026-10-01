import crypto from 'node:crypto'
import express from 'express'
import cors from 'cors'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { db } from './db.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3001
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'savok888'

app.use(cors())
app.use(express.json({ limit: '10mb' }))

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + '_cs2_salt_2026').digest('hex')
}

// Middleware for Admin Authentication
function requireAdmin(req, res, next) {
  const auth = req.headers['x-admin-key'] || req.query.admin_key
  if (auth !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Admin Secret' })
  }
  next()
}

// ----------------------------------------------------
// PUBLIC / CLIENT API
// ----------------------------------------------------

// Health check & Server Status
app.get('/api/status', (req, res) => {
  const stats = db.prepare('SELECT COUNT(*) as players FROM players').get()
  res.json({
    online: true,
    server: 'CS2 Upgrader Online Core',
    playersCount: stats.players,
    time: Date.now()
  })
})

// Register new account
app.post('/api/auth/register', (req, res) => {
  const {
    username,
    password,
    nickname,
    balance = 750000,
    level = 1,
    xp = 0,
    upgradesCount = 0,
    wonCount = 0,
    biggestWin = 0,
    inventory = [],
    quests = [],
    questStats = {}
  } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: 'Укажите логин и пароль' })
  }

  const cleanUser = username.trim().toLowerCase()
  if (cleanUser.length < 3 || cleanUser.length > 24) {
    return res.status(400).json({ error: 'Логин должен содержать от 3 до 24 символов' })
  }
  if (!/^[a-zA-Z0-9_]+$/.test(cleanUser)) {
    return res.status(400).json({ error: 'Логин может содержать только латинские буквы, цифры и _' })
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Пароль должен быть не менее 4 символов' })
  }

  const existing = db.prepare('SELECT id FROM players WHERE LOWER(username) = ?').get(cleanUser)
  if (existing) {
    return res.status(400).json({ error: 'Игрок с таким логином уже зарегистрирован' })
  }

  const id = `usr_${crypto.randomBytes(6).toString('hex')}`
  const passHash = hashPassword(password)
  const token = `tok_${crypto.randomBytes(24).toString('hex')}`
  const now = Date.now()
  const displayNick = (nickname || cleanUser).trim()

  db.prepare(`
    INSERT INTO players (
      id, username, nickname, password_hash, auth_token,
      balance, level, xp, upgrades_count, won_count, biggest_win,
      inventory_json, quests_json, quest_stats_json, last_active, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, cleanUser, displayNick, passHash, token,
    balance, level, xp, upgradesCount, wonCount, biggestWin,
    JSON.stringify(inventory), JSON.stringify(quests), JSON.stringify(questStats), now, now
  )

  res.json({
    success: true,
    token,
    player: {
      id,
      username: cleanUser,
      nickname: displayNick,
      balance,
      level,
      xp,
      upgradesCount,
      wonCount,
      biggestWin,
      inventory,
      quests,
      questStats
    }
  })
})

// Login to existing account
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body
  if (!username || !password) {
    return res.status(400).json({ error: 'Укажите логин и пароль' })
  }

  const cleanUser = username.trim().toLowerCase()
  const player = db.prepare('SELECT * FROM players WHERE LOWER(username) = ?').get(cleanUser)

  if (!player) {
    return res.status(401).json({ error: 'Аккаунт с таким логином не найден' })
  }

  if (player.banned === 1) {
    return res.status(403).json({ error: 'Аккаунт заблокирован администратором' })
  }

  const passHash = hashPassword(password)
  if (player.password_hash !== passHash) {
    return res.status(401).json({ error: 'Неверный пароль' })
  }

  const token = `tok_${crypto.randomBytes(24).toString('hex')}`
  const now = Date.now()
  db.prepare('UPDATE players SET auth_token = ?, last_active = ? WHERE id = ?').run(token, now, player.id)

  let inventory = []
  let quests = []
  let questStats = {}
  try { inventory = JSON.parse(player.inventory_json || '[]') } catch {}
  try { quests = JSON.parse(player.quests_json || '[]') } catch {}
  try { questStats = JSON.parse(player.quest_stats_json || '{}') } catch {}

  res.json({
    success: true,
    token,
    player: {
      id: player.id,
      username: player.username,
      nickname: player.nickname,
      balance: player.balance,
      level: player.level,
      xp: player.xp,
      upgradesCount: player.upgrades_count,
      wonCount: player.won_count,
      biggestWin: player.biggest_win,
      inventory,
      quests,
      questStats
    }
  })
})

// Sync player profile from APK
app.post('/api/player/sync', (req, res) => {
  const {
    id,
    nickname = 'Player',
    balance = 750000,
    level = 1,
    xp = 0,
    upgradesCount = 0,
    wonCount = 0,
    biggestWin = 0,
    inventory = []
  } = req.body

  if (!id) {
    return res.status(400).json({ error: 'Missing player id' })
  }

  const now = Date.now()
  const existing = db.prepare('SELECT * FROM players WHERE id = ?').get(id)

  if (!existing) {
    // Register new player
    db.prepare(`
      INSERT INTO players (id, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, inventory_json, last_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, nickname, balance, level, xp, upgradesCount, wonCount, biggestWin, JSON.stringify(inventory), now, now)

    return res.json({
      success: true,
      action: 'registered',
      player: { id, nickname, balance, level, xp }
    })
  }

  if (existing.banned === 1) {
    return res.status(403).json({ error: 'Player account is suspended by administrator' })
  }

  // If admin granted balance on the server, we preserve server balance bonus if higher
  const finalBalance = Math.max(existing.balance, balance)

  // Update existing player
  db.prepare(`
    UPDATE players SET
      nickname = ?,
      balance = ?,
      level = ?,
      xp = ?,
      upgrades_count = ?,
      won_count = ?,
      biggest_win = ?,
      inventory_json = ?,
      last_active = ?
    WHERE id = ?
  `).run(
    nickname || existing.nickname,
    finalBalance,
    Math.max(existing.level, level),
    Math.max(existing.xp, xp),
    Math.max(existing.upgrades_count, upgradesCount),
    Math.max(existing.won_count, wonCount),
    Math.max(existing.biggest_win, biggestWin),
    JSON.stringify(inventory),
    now,
    id
  )

  res.json({
    success: true,
    action: 'synced',
    balance: finalBalance,
    level: Math.max(existing.level, level),
    xp: Math.max(existing.xp, xp)
  })
})

// Redeem Promo Code
app.post('/api/promocodes/redeem', (req, res) => {
  const { playerId, code } = req.body
  if (!playerId || !code) {
    return res.status(400).json({ error: 'Требуется ID игрока и промокод' })
  }

  const cleanCode = code.trim().toUpperCase()
  const promo = db.prepare('SELECT * FROM promocodes WHERE code = ?').get(cleanCode)

  if (!promo) {
    return res.status(404).json({ error: 'Промокод не найден или устарел' })
  }

  if (promo.max_uses > 0 && promo.used_count >= promo.max_uses) {
    return res.status(400).json({ error: 'Лимит активаций этого промокода исчерпан' })
  }

  // Check if player already redeemed
  const alreadyUsed = db.prepare('SELECT id FROM promocode_redemptions WHERE code = ? AND player_id = ?').get(cleanCode, playerId)
  if (alreadyUsed) {
    return res.status(400).json({ error: 'Вы уже активировали этот промокод ранее' })
  }

  const now = Date.now()

  // Record redemption and increment count
  db.prepare('INSERT INTO promocode_redemptions (code, player_id, redeemed_at) VALUES (?, ?, ?)').run(cleanCode, playerId, now)
  db.prepare('UPDATE promocodes SET used_count = used_count + 1 WHERE code = ?').run(cleanCode)

  // Credit player balance in DB
  const player = db.prepare('SELECT balance FROM players WHERE id = ?').get(playerId)
  let newBalance = promo.amount
  if (player) {
    newBalance = player.balance + promo.amount
    db.prepare('UPDATE players SET balance = ? WHERE id = ?').run(newBalance, playerId)
  }

  // Log redemption
  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'PROMOCODE_REDEEM',
    `Player ${playerId} redeemed ${cleanCode} for ${promo.amount / 100} RUB`,
    now
  )

  res.json({
    success: true,
    code: cleanCode,
    amountKopecks: promo.amount,
    amountRub: promo.amount / 100,
    newBalance,
    message: `🎁 Промокод ${cleanCode} успешно активирован (+${(promo.amount / 100).toLocaleString('ru-RU')} ₽)!`
  })
})

// ----------------------------------------------------
// ADMIN API (Authorized via x-admin-key)
// ----------------------------------------------------

// Admin Dashboard Overview
app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const playersCount = db.prepare('SELECT COUNT(*) as c FROM players').get().c
  const activeToday = db.prepare('SELECT COUNT(*) as c FROM players WHERE last_active > ?').get(Date.now() - 86400000).c
  const totalBalance = db.prepare('SELECT SUM(balance) as s FROM players').get().s || 0
  const totalUpgrades = db.prepare('SELECT SUM(upgrades_count) as s FROM players').get().s || 0
  const promoCount = db.prepare('SELECT COUNT(*) as c FROM promocodes').get().c

  res.json({
    playersCount,
    activeToday,
    totalBalanceRub: totalBalance / 100,
    totalUpgrades,
    promoCount
  })
})

// List all players
app.get('/api/admin/players', requireAdmin, (req, res) => {
  const players = db.prepare(`
    SELECT id, username, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, banned, last_active, created_at
    FROM players
    ORDER BY last_active DESC
    LIMIT 200
  `).all()

  res.json(players)
})

// Get single player with inventory
app.get('/api/admin/players/:id', requireAdmin, (req, res) => {
  const player = db.prepare('SELECT * FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  let inventory = []
  try {
    inventory = JSON.parse(player.inventory_json || '[]')
  } catch {
    inventory = []
  }

  res.json({
    ...player,
    inventory
  })
})

// Grant or deduct player balance
app.post('/api/admin/players/:id/balance', requireAdmin, (req, res) => {
  const { amountRub, amountKopecks } = req.body
  const delta = amountKopecks !== undefined ? Number(amountKopecks) : Math.round(Number(amountRub) * 100)

  if (isNaN(delta)) {
    return res.status(400).json({ error: 'Invalid amount' })
  }

  const player = db.prepare('SELECT balance, nickname FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  const newBalance = Math.max(0, player.balance + delta)
  db.prepare('UPDATE players SET balance = ? WHERE id = ?').run(newBalance, req.params.id)

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'ADMIN_BALANCE_ADJUST',
    `Adjusted player ${player.nickname} (${req.params.id}) by ${delta / 100} RUB (new balance: ${newBalance / 100} RUB)`,
    Date.now()
  )

  res.json({
    success: true,
    playerId: req.params.id,
    deltaRub: delta / 100,
    newBalanceKopecks: newBalance,
    newBalanceRub: newBalance / 100
  })
})

// Ban / Unban player
app.post('/api/admin/players/:id/ban', requireAdmin, (req, res) => {
  const { banned } = req.body
  db.prepare('UPDATE players SET banned = ? WHERE id = ?').run(banned ? 1 : 0, req.params.id)
  res.json({ success: true, playerId: req.params.id, banned: !!banned })
})

// List Promo Codes
app.get('/api/admin/promocodes', requireAdmin, (req, res) => {
  const codes = db.prepare('SELECT * FROM promocodes ORDER BY created_at DESC').all()
  res.json(codes)
})

// Create Promo Code
app.post('/api/admin/promocodes', requireAdmin, (req, res) => {
  const { code, amountRub, maxUses = 0 } = req.body
  if (!code || !amountRub) {
    return res.status(400).json({ error: 'Code name and amount in RUB are required' })
  }

  const cleanCode = code.trim().toUpperCase()
  const amountKopecks = Math.round(Number(amountRub) * 100)

  try {
    db.prepare(`
      INSERT INTO promocodes (code, amount, max_uses, used_count, created_at)
      VALUES (?, ?, ?, 0, ?)
    `).run(cleanCode, amountKopecks, Number(maxUses), Date.now())

    res.json({
      success: true,
      code: cleanCode,
      amountRub: Number(amountRub),
      maxUses: Number(maxUses)
    })
  } catch (err) {
    if (String(err).includes('UNIQUE')) {
      return res.status(400).json({ error: 'Промокод с таким именем уже существует!' })
    }
    res.status(500).json({ error: String(err) })
  }
})

// Delete Promo Code
app.delete('/api/admin/promocodes/:code', requireAdmin, (req, res) => {
  const cleanCode = req.params.code.trim().toUpperCase()
  db.prepare('DELETE FROM promocodes WHERE code = ?').run(cleanCode)
  res.json({ success: true, deletedCode: cleanCode })
})

// ----------------------------------------------------
// WEB ADMIN DASHBOARD (Browser-accessible at /admin)
// ----------------------------------------------------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'))
})

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[CS2 Upgrader Server] Running on http://0.0.0.0:${PORT}`)
  console.log(`[Admin Panel] Accessible at http://localhost:${PORT}/admin (Key: ${ADMIN_SECRET})`)
})
