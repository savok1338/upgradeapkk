import crypto from 'node:crypto'
import express from 'express'
import cors from 'cors'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { db, getAppConfig, setAppConfig } from './db.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3001
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'savokadm8'

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

// Middleware to enforce minimum client version for outdated APKs
function checkClientVersion(req, res, next) {
  const forceEnabled = getAppConfig('force_update_enabled', '1') === '1'
  if (!forceEnabled) return next()

  const minVersionCode = Number(getAppConfig('min_version_code', '33'))
  const clientVersion = Number((req.body && req.body.versionCode) || req.headers['x-client-version'] || 0)
  const telegramChannel = getAppConfig('telegram_channel', '@upgradermobile')
  const telegramUrl = getAppConfig('telegram_url', 'https://t.me/upgradermobile')
  const updateMessage = getAppConfig('update_message', `Вышла новая версия CS2 Upgrader! Скачайте обновление в Telegram: ${telegramChannel}`)

  if (clientVersion < minVersionCode) {
    return res.status(426).json({
      error: `⚠️ Версия игры устарела! Скачайте обновление в нашем Telegram канале: ${telegramChannel}`,
      updateRequired: true,
      minVersionCode,
      clientVersion,
      telegramChannel,
      telegramUrl,
      updateMessage
    })
  }
  next()
}

// ----------------------------------------------------
// PUBLIC / CLIENT API
// ----------------------------------------------------

// Health check, Server Status & Version Control
app.get('/api/status', (req, res) => {
  const stats = db.prepare('SELECT COUNT(*) as players FROM players').get()
  const minVersionCode = Number(getAppConfig('min_version_code', '33'))
  const latestVersionName = getAppConfig('latest_version_name', '3.3')
  const telegramChannel = getAppConfig('telegram_channel', '@upgradermobile')
  const telegramUrl = getAppConfig('telegram_url', 'https://t.me/upgradermobile')
  const updateMessage = getAppConfig('update_message', `Вышла новая версия CS2 Upgrader! Скачайте обновление в нашем официальном Telegram канале: ${telegramChannel}`)
  const forceUpdateEnabled = getAppConfig('force_update_enabled', '1') === '1'
  const econResetAt = Number(getAppConfig('econ_reset_at', '0'))

  res.json({
    online: true,
    server: 'CS2 Upgrader Online Core',
    playersCount: stats.players,
    minVersionCode,
    latestVersionName,
    telegramChannel,
    telegramUrl,
    updateMessage,
    forceUpdateEnabled,
    econResetAt,
    time: Date.now()
  })
})

// Register new account
app.post('/api/auth/register', checkClientVersion, (req, res) => {
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
app.post('/api/auth/login', checkClientVersion, (req, res) => {
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

  // Admin edited this player's inventory while they were away — apply the
  // pending edit at login so it survives no matter what the client pushes later
  if (player.pending_inventory_json) {
    try {
      const pendingInv = JSON.parse(player.pending_inventory_json)
      if (Array.isArray(pendingInv)) {
        inventory = pendingInv
        db.prepare('UPDATE players SET inventory_json = ?, pending_inventory_json = NULL WHERE id = ?')
          .run(player.pending_inventory_json, player.id)
      }
    } catch {
      db.prepare('UPDATE players SET pending_inventory_json = NULL WHERE id = ?').run(player.id)
    }
  }

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
app.post('/api/player/sync', checkClientVersion, (req, res) => {
  const {
    id,
    authToken,
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

  if (!id) {
    return res.status(400).json({ error: 'Missing player id' })
  }

  const now = Date.now()
  const existing = db.prepare('SELECT * FROM players WHERE id = ?').get(id)

  if (!existing) {
    // Account was deleted by admin (or never existed) — never resurrect it
    return res.status(401).json({ error: 'Аккаунт не найден. Авторизуйтесь заново.', logout: true })
  }

  // Registered accounts must present their auth token — keeps deleted
  // accounts deleted and prevents overwriting other players by id
  if (existing.auth_token && existing.auth_token !== authToken) {
    return res.status(401).json({ error: 'Сессия недействительна. Авторизуйтесь заново.', logout: true })
  }

  if (existing.banned === 1) {
    return res.status(403).json({ error: 'Аккаунт заблокирован администратором', banned: true })
  }

  // Check if admin granted any pending bonus to this player from admin dashboard
  let bonusApplied = 0
  let finalBalance = Number(balance)
  if (existing.pending_bonus && existing.pending_bonus > 0) {
    bonusApplied = Number(existing.pending_bonus)
    finalBalance += bonusApplied
    db.prepare('UPDATE players SET pending_bonus = 0 WHERE id = ?').run(id)
  }

  // Update existing player with exact client state (authoritative client progress)
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
      quests_json = ?,
      quest_stats_json = ?,
      last_active = ?
    WHERE id = ?
  `).run(
    nickname || existing.nickname,
    finalBalance,
    level,
    xp,
    upgradesCount,
    wonCount,
    biggestWin,
    JSON.stringify(inventory),
    JSON.stringify(quests),
    JSON.stringify(questStats),
    now,
    id
  )

  // Admin edited this player's inventory — apply it over the client push so the
  // edit survives, and hand the final list back to the client
  let inventoryOverride = null
  if (existing.pending_inventory_json) {
    try {
      inventoryOverride = JSON.parse(existing.pending_inventory_json)
      db.prepare('UPDATE players SET inventory_json = ?, pending_inventory_json = NULL WHERE id = ?')
        .run(existing.pending_inventory_json, id)
    } catch {
      db.prepare('UPDATE players SET pending_inventory_json = NULL WHERE id = ?').run(id)
    }
  }

  res.json({
    success: true,
    action: 'synced',
    balance: finalBalance,
    bonusApplied,
    level,
    xp,
    inventoryOverride,
    econResetAt: Number(getAppConfig('econ_reset_at', '0'))
  })
})

// Redeem Promo Code
app.post('/api/promocodes/redeem', checkClientVersion, (req, res) => {
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
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : ''
  let players
  if (q) {
    const like = `%${q}%`
    players = db.prepare(`
      SELECT id, username, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, banned, last_active, created_at
      FROM players
      WHERE nickname LIKE ? OR LOWER(username) LIKE LOWER(?) OR id LIKE ?
      ORDER BY last_active DESC
      LIMIT 500
    `).all(like, like, like)
  } else {
    players = db.prepare(`
      SELECT id, username, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, banned, last_active, created_at
      FROM players
      ORDER BY last_active DESC
      LIMIT 500
    `).all()
  }

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

  const player = db.prepare('SELECT balance, pending_bonus, nickname FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  const newBalance = Math.max(0, player.balance + delta)
  const newPending = (player.pending_bonus || 0) + delta

  db.prepare('UPDATE players SET balance = ?, pending_bonus = ? WHERE id = ?').run(newBalance, newPending, req.params.id)

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

// Set player inventory (admin edit — applied on the player's next sync)
app.post('/api/admin/players/:id/inventory', requireAdmin, (req, res) => {
  const { items } = req.body
  if (!Array.isArray(items)) {
    return res.status(400).json({ error: 'Field "items" must be an array' })
  }

  const player = db.prepare('SELECT id, nickname FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  let serialized
  try {
    serialized = JSON.stringify(items)
  } catch {
    return res.status(400).json({ error: 'Inventory is not serializable' })
  }

  db.prepare('UPDATE players SET pending_inventory_json = ? WHERE id = ?').run(serialized, req.params.id)

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'ADMIN_INVENTORY_EDIT',
    `Queued inventory edit for ${player.nickname} (${req.params.id}): ${items.length} items (applies on next sync)`,
    Date.now()
  )

  res.json({
    success: true,
    playerId: req.params.id,
    itemCount: items.length,
    message: 'Изменения применятся при следующем входе игрока'
  })
})

// Reset a player's password (admin)
app.post('/api/admin/players/:id/password', requireAdmin, (req, res) => {
  const { password } = req.body
  if (!password || String(password).length < 4) {
    return res.status(400).json({ error: 'Пароль должен быть не менее 4 символов' })
  }

  const player = db.prepare('SELECT id, nickname, username FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  const passHash = hashPassword(String(password))
  const token = `tok_${crypto.randomBytes(24).toString('hex')}`
  db.prepare('UPDATE players SET password_hash = ?, auth_token = ? WHERE id = ?').run(passHash, token, req.params.id)

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'ADMIN_PASSWORD_RESET',
    `Password reset for ${player.nickname} (@${player.username || 'guest'}) ID ${req.params.id}; session token rotated`,
    Date.now()
  )

  res.json({ success: true, playerId: req.params.id, message: 'Пароль обновлён, старые сессии сброшены' })
})

// Ban / Unban player
app.post('/api/admin/players/:id/ban', requireAdmin, (req, res) => {
  const player = db.prepare('SELECT id, nickname, username, banned FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  const newBanned = req.body.banned !== undefined ? (req.body.banned ? 1 : 0) : (player.banned === 1 ? 0 : 1)
  db.prepare('UPDATE players SET banned = ? WHERE id = ?').run(newBanned, req.params.id)

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    newBanned === 1 ? 'ADMIN_BAN_PLAYER' : 'ADMIN_UNBAN_PLAYER',
    `${newBanned === 1 ? 'Banned' : 'Unbanned'} player ${player.nickname} (@${player.username || 'guest'}) ID ${req.params.id}`,
    Date.now()
  )

  res.json({ success: true, playerId: req.params.id, banned: newBanned === 1 })
})

// Delete player account permanently
app.delete('/api/admin/players/:id', requireAdmin, (req, res) => {
  const player = db.prepare('SELECT id, nickname, username FROM players WHERE id = ?').get(req.params.id)
  if (!player) return res.status(404).json({ error: 'Player not found' })

  db.prepare('DELETE FROM players WHERE id = ?').run(req.params.id)
  try { db.prepare('DELETE FROM promocode_redemptions WHERE player_id = ?').run(req.params.id) } catch {}

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'ADMIN_DELETE_PLAYER',
    `Permanently deleted player ${player.nickname} (@${player.username || 'guest'}) ID ${req.params.id}`,
    Date.now()
  )

  res.json({ success: true, deletedId: req.params.id })
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
// ADMIN APP CONFIG / VERSION CONTROL
// ----------------------------------------------------

// Get current version control & system configs
app.get('/api/admin/config', requireAdmin, (req, res) => {
  const configs = db.prepare('SELECT key, value FROM app_config').all()
  const map = {}
  for (const c of configs) map[c.key] = c.value
  res.json(map)
})

// Update version control configs
app.post('/api/admin/config', requireAdmin, (req, res) => {
  const { min_version_code, latest_version_name, telegram_channel, telegram_url, update_message, force_update_enabled, econ_reset_at } = req.body
  if (min_version_code !== undefined) setAppConfig('min_version_code', min_version_code)
  if (latest_version_name !== undefined) setAppConfig('latest_version_name', latest_version_name)
  if (telegram_channel !== undefined) setAppConfig('telegram_channel', telegram_channel)
  if (telegram_url !== undefined) setAppConfig('telegram_url', telegram_url)
  if (update_message !== undefined) setAppConfig('update_message', update_message)
  if (force_update_enabled !== undefined) setAppConfig('force_update_enabled', force_update_enabled ? '1' : '0')
  if (econ_reset_at !== undefined) {
    setAppConfig('econ_reset_at', String(Number(econ_reset_at) || Date.now()))
    db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
      'ADMIN_ECON_RESET',
      `Economy reset marker bumped to ${getAppConfig('econ_reset_at', '0')} — all clients will wipe progress on next sync`,
      Date.now()
    )
  }

  res.json({ success: true, message: 'Настройки версий успешно обновлены' })
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
