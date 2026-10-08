import crypto from 'node:crypto'
import express from 'express'
import cors from 'cors'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { db, getAppConfig, setAppConfig } from './db.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3001
let ADMIN_SECRET = getAppConfig('admin_secret') || process.env.ADMIN_SECRET || 'savokadm8'
const ONLINE_WINDOW_MS = 90 * 1000

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

  const minVersionCode = Number(getAppConfig('min_version_code', '35'))
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
  const minVersionCode = Number(getAppConfig('min_version_code', '35'))
  const latestVersionName = getAppConfig('latest_version_name', '3.5')
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

  // If admin reset this player's economy (or global economy), wipe client cleanly without letting stale client state overwrite DB
  const clientEconAck = Number(req.body.econResetAck) || 0
  const globalEconMarker = Number(getAppConfig('econ_reset_at', '0')) || 0
  const playerEconMarker = Math.max(Number(existing.economy_reset_at) || 0, globalEconMarker)

  if (playerEconMarker > clientEconAck) {
    return res.json({
      success: true,
      action: 'reset',
      econResetAt: playerEconMarker,
      balance: existing.balance,
      bonusApplied: 0,
      level: existing.level,
      xp: existing.xp,
      inventoryOverride: []
    })
  }

  // Check if admin granted any pending bonus to this player from admin dashboard or received transfers
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
    econResetAt: playerEconMarker
  })
})

// Public player directory and profiles
app.get('/api/players', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : ''
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50))
  const like = `%${q}%`
  const rows = db.prepare(`SELECT id, nickname, level, xp, upgrades_count, won_count, biggest_win, created_at, last_active, profile_visibility, bio, avatar_url, COALESCE(json_array_length(inventory_json), 0) AS skins_count FROM players WHERE banned = 0 AND profile_visibility = 'public' AND (? = '' OR nickname LIKE ? OR id LIKE ?) ORDER BY last_active DESC LIMIT ?`).all(q, like, like, limit)
  res.json(rows.map(p => ({
    id: p.id,
    nickname: p.nickname,
    level: p.level,
    xp: p.xp,
    upgradesCount: p.upgrades_count,
    wonCount: p.won_count,
    biggestWin: p.biggest_win,
    skinsCount: p.skins_count,
    createdAt: p.created_at,
    lastActive: p.last_active,
    online: (Date.now() - p.last_active) <= ONLINE_WINDOW_MS,
    bio: p.bio || '',
    avatarUrl: p.avatar_url || null
  })))
})

// Public profile: best drop & upgrade stats, NEVER returns balance or inventory of other player
app.get('/api/players/:id', (req, res) => {
  const p = db.prepare('SELECT id, nickname, level, xp, upgrades_count, won_count, biggest_win, created_at, last_active, profile_visibility, bio, avatar_url, COALESCE(json_array_length(inventory_json), 0) AS skins_count FROM players WHERE id = ? AND banned = 0').get(req.params.id)
  if (!p || p.profile_visibility !== 'public') return res.status(404).json({ error: 'Игрок не найден' })
  res.json({
    id: p.id,
    nickname: p.nickname,
    level: p.level,
    xp: p.xp,
    upgradesCount: p.upgrades_count,
    wonCount: p.won_count,
    biggestWin: p.biggest_win,
    skinsCount: p.skins_count,
    createdAt: p.created_at,
    lastActive: p.last_active,
    online: (Date.now() - p.last_active) <= ONLINE_WINDOW_MS,
    bio: p.bio || '',
    avatarUrl: p.avatar_url || null
  })
})

// Real Leaderboards: supports sorting by balance, skins count, level, upgrades, wins, biggest win
app.get('/api/leaderboards', (req, res) => {
  const metric = req.query.metric || 'balance'
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50))
  let orderBy = 'balance DESC, id ASC'
  if (metric === 'skins') {
    orderBy = 'COALESCE(json_array_length(inventory_json), 0) DESC, id ASC'
  } else if (metric === 'level') {
    orderBy = 'level DESC, xp DESC, id ASC'
  } else if (metric === 'upgrades') {
    orderBy = 'upgrades_count DESC, id ASC'
  } else if (metric === 'wonCount') {
    orderBy = 'won_count DESC, id ASC'
  } else if (metric === 'biggestWin' || metric === 'drop') {
    orderBy = 'biggest_win DESC, id ASC'
  }

  const query = `
    SELECT
      id, nickname, level, xp, balance, upgrades_count, won_count, biggest_win,
      COALESCE(json_array_length(inventory_json), 0) AS skins_count,
      last_active,
      ROW_NUMBER() OVER (ORDER BY ${orderBy}) AS rank
    FROM players
    WHERE banned = 0
    ORDER BY ${orderBy}
    LIMIT ?
  `
  const rows = db.prepare(query).all(limit)
  res.json(rows.map(p => ({
    id: p.id,
    nickname: p.nickname,
    level: p.level,
    xp: p.xp,
    balance: p.balance,
    upgradesCount: p.upgrades_count,
    wonCount: p.won_count,
    biggestWin: p.biggest_win,
    skinsCount: p.skins_count,
    rank: p.rank,
    lastActive: p.last_active,
    online: (Date.now() - p.last_active) <= ONLINE_WINDOW_MS
  })))
})

// Player heartbeat / profile update
app.post('/api/player/heartbeat', (req, res) => {
  const { id, authToken } = req.body || {}
  const p = db.prepare('SELECT id FROM players WHERE id = ? AND auth_token = ? AND banned = 0').get(id, authToken)
  if (!p) return res.status(401).json({ error: 'Unauthorized' })
  db.prepare('UPDATE players SET last_active = ? WHERE id = ?').run(Date.now(), id)
  res.json({ success: true, onlineUntil: Date.now() + ONLINE_WINDOW_MS })
})

app.patch('/api/player/profile', (req, res) => {
  const { id, authToken, nickname, bio, avatarUrl, profileVisibility, showInventory } = req.body || {}
  const p = db.prepare('SELECT id FROM players WHERE id = ? AND auth_token = ?').get(id, authToken)
  if (!p) return res.status(401).json({ error: 'Unauthorized' })
  if (nickname !== undefined && (String(nickname).trim().length < 1 || String(nickname).length > 32)) return res.status(400).json({ error: 'Invalid nickname' })
  const visibility = profileVisibility === 'private' ? 'private' : 'public'
  db.prepare('UPDATE players SET nickname = COALESCE(?, nickname), bio = COALESCE(?, bio), avatar_url = COALESCE(?, avatar_url), profile_visibility = ?, show_inventory = ? WHERE id = ?').run(nickname === undefined ? null : String(nickname).trim(), bio === undefined ? null : String(bio).slice(0, 280), avatarUrl === undefined ? null : String(avatarUrl).slice(0, 500), visibility, showInventory ? 1 : 0, id)
  res.json({ success: true })
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

// Chat API (with live sender online status & aliases)
function getChatMessagesHandler(req, res) {
  const channel = String(req.query.channel || 'global').slice(0, 32)
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 60))
  const rows = db.prepare(`
    SELECT
      c.id, c.channel, c.sender_id AS senderId, p.nickname, c.body, c.created_at AS createdAt, p.last_active AS lastActive
    FROM chat_messages c
    LEFT JOIN players p ON p.id = c.sender_id
    WHERE c.channel = ? AND c.deleted_at IS NULL
    ORDER BY c.id DESC
    LIMIT ?
  `).all(channel, limit)

  res.json(rows.reverse().map(m => ({
    id: m.id,
    channel: m.channel,
    senderId: m.senderId,
    nickname: m.nickname || 'Игрок',
    body: m.body,
    text: m.body,
    createdAt: m.createdAt,
    online: m.lastActive ? (Date.now() - m.lastActive) <= ONLINE_WINDOW_MS : false
  })))
}

function postChatMessageHandler(req, res) {
  const { id, authToken, body, text, channel = 'global' } = req.body || {}
  const p = db.prepare('SELECT id, nickname FROM players WHERE id = ? AND auth_token = ? AND banned = 0').get(id, authToken)
  if (!p) return res.status(401).json({ error: 'Необходима авторизация' })
  const messageText = String(body || text || '').trim()
  if (!messageText || messageText.length > 500) return res.status(400).json({ error: 'Длина сообщения от 1 до 500 символов' })
  const now = Date.now()
  const recent = db.prepare('SELECT COUNT(*) AS c FROM chat_messages WHERE sender_id = ? AND created_at > ?').get(id, now - 10000).c
  if (recent >= 5) return res.status(429).json({ error: 'Слишком частая отправка сообщений' })

  const result = db.prepare('INSERT INTO chat_messages (channel, sender_id, body, created_at) VALUES (?, ?, ?, ?)').run(String(channel).slice(0, 32), id, messageText, now)
  db.prepare('UPDATE players SET last_active = ? WHERE id = ?').run(now, id)

  res.status(201).json({
    id: Number(result.lastInsertRowid),
    channel,
    senderId: id,
    nickname: p.nickname,
    body: messageText,
    text: messageText,
    createdAt: now,
    online: true
  })
}

app.get('/api/chat/messages', getChatMessagesHandler)
app.post('/api/chat/messages', postChatMessageHandler)
app.get('/api/community/messages', getChatMessagesHandler)
app.post('/api/community/messages', postChatMessageHandler)

app.delete('/api/admin/chat/messages/:id', requireAdmin, (req, res) => {
  db.prepare('UPDATE chat_messages SET deleted_at = ? WHERE id = ?').run(Date.now(), Number(req.params.id))
  res.json({ success: true })
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
      SELECT id, username, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, banned, last_active, created_at, (last_active >= ? ) AS online
      FROM players
      WHERE (nickname LIKE ? OR LOWER(username) LIKE LOWER(?) OR id LIKE ?)
      ORDER BY last_active DESC
      LIMIT 500
    `).all(Date.now() - ONLINE_WINDOW_MS, like, like, like)
  } else {
    players = db.prepare(`
      SELECT id, username, nickname, balance, level, xp, upgrades_count, won_count, biggest_win, banned, last_active, created_at, (last_active >= ?) AS online
      FROM players
      ORDER BY last_active DESC
      LIMIT 500
    `).all(Date.now() - ONLINE_WINDOW_MS)
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

// Delete selected/all inventory items
app.post('/api/admin/players/:id/inventory/delete', requireAdmin, (req, res) => {
  const { itemIds = [], marketNames = [], all = false, confirm = false } = req.body || {}
  if (all && !confirm) return res.status(400).json({ error: 'confirm=true required for deleting all items' })
  const p = db.prepare('SELECT id, nickname, inventory_json FROM players WHERE id = ?').get(req.params.id)
  if (!p) return res.status(404).json({ error: 'Player not found' })
  let items; try { items = JSON.parse(p.inventory_json || '[]') } catch { items = [] }
  const ids = new Set(Array.isArray(itemIds) ? itemIds.map(String) : [])
  const names = new Set(Array.isArray(marketNames) ? marketNames.map(String) : [])
  const remaining = all ? [] : items.filter(x => !ids.has(String(x?.id)) && !names.has(String(x?.marketName)))
  const serialized = JSON.stringify(remaining)
  db.prepare('UPDATE players SET inventory_json = ?, pending_inventory_json = ? WHERE id = ?').run(serialized, serialized, p.id)
  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run('ADMIN_INVENTORY_DELETE', `Deleted ${items.length - remaining.length} items from ${p.nickname} (${p.id})`, Date.now())
  res.json({ success: true, deletedCount: items.length - remaining.length, remainingCount: remaining.length })
})

// Per-player economy reset
app.post('/api/admin/players/:id/economy-reset', requireAdmin, (req, res) => {
  const { confirm = false, initialBalanceKopecks = 750000, clearInventory = true, clearStats = true } = req.body || {}
  if (!confirm) return res.status(400).json({ error: 'confirm=true required' })
  const p = db.prepare('SELECT id, nickname FROM players WHERE id = ?').get(req.params.id)
  if (!p) return res.status(404).json({ error: 'Player not found' })
  const now = Date.now()
  const fields = ['balance = ?', 'pending_bonus = 0', 'economy_reset_at = ?', 'pending_inventory_json = NULL']
  const args = [Math.max(0, Number(initialBalanceKopecks) || 0), now]
  if (clearStats) { fields.push('level = 1', 'xp = 0', 'upgrades_count = 0', 'won_count = 0', 'biggest_win = 0', "quests_json = '[]'", "quest_stats_json = '{}'") }
  if (clearInventory) { fields.push("inventory_json = '[]'") }
  db.prepare(`UPDATE players SET ${fields.join(', ')} WHERE id = ?`).run(...args, p.id)
  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run('ADMIN_PLAYER_ECON_RESET', `Reset economy for ${p.nickname} (${p.id})`, now)
  res.json({ success: true, playerId: p.id, economyResetAt: now })
})

// Player-to-player transfer (server-authoritative, idempotent)
function transferHandler(req, res) {
  const { id, authToken, toPlayerId, amountKopecks, amountRub, idempotencyKey, comment } = req.body || {}
  const rawAmount = amountKopecks !== undefined ? Number(amountKopecks) : (Number(amountRub) * 100)
  const amount = Math.floor(rawAmount)
  const cleanComment = typeof comment === 'string' ? comment.trim().slice(0, 120) : null
  const key = idempotencyKey || `idem_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
  if (!toPlayerId || !Number.isSafeInteger(amount) || amount <= 0 || id === toPlayerId) {
    return res.status(400).json({ error: 'Некорректная сумма перевода или получатель' })
  }
  const sender = db.prepare('SELECT id, balance, nickname FROM players WHERE id = ? AND auth_token = ? AND banned = 0').get(id, authToken)
  const recipient = db.prepare('SELECT id, nickname FROM players WHERE id = ? AND banned = 0').get(toPlayerId)
  if (!sender) return res.status(401).json({ error: 'Сессия недействительна' })
  if (!recipient) return res.status(404).json({ error: 'Получатель не найден' })
  if (sender.balance < amount) return res.status(400).json({ error: 'Недостаточно средств на балансе' })

  const old = db.prepare('SELECT * FROM wallet_transfers WHERE idempotency_key = ?').get(String(key))
  if (old) {
    return res.json({
      success: old.status === 'completed',
      transfer: old,
      balanceKopecks: sender.balance,
      message: 'Перевод уже был обработан'
    })
  }

  const transferId = `tr_${crypto.randomBytes(12).toString('hex')}`
  const now = Date.now()
  try {
    db.exec('BEGIN IMMEDIATE')
    const updated = db.prepare('UPDATE players SET balance = balance - ?, last_active = ? WHERE id = ? AND balance >= ?').run(amount, now, id, amount)
    if (updated.changes !== 1) {
      db.exec('ROLLBACK')
      return res.status(400).json({ error: 'Недостаточно средств на балансе' })
    }
    // Credit recipient balance AND bump pending_bonus so recipient's next client sync preserves the transfer
    db.prepare('UPDATE players SET balance = balance + ?, pending_bonus = pending_bonus + ? WHERE id = ?').run(amount, amount, toPlayerId)
    const balances = db.prepare('SELECT id, balance FROM players WHERE id IN (?, ?)').all(id, toPlayerId)
    db.prepare('INSERT INTO wallet_transfers (id, from_player_id, to_player_id, amount, idempotency_key, created_at, completed_at, comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(transferId, id, toPlayerId, amount, String(key), now, now, cleanComment)
    for (const b of balances) {
      db.prepare('INSERT INTO wallet_transactions (player_id, transfer_id, delta, balance_after, type, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(b.id, transferId, b.id === id ? -amount : amount, b.balance, 'transfer', now)
    }
    db.exec('COMMIT')
  } catch (e) {
    try { db.exec('ROLLBACK') } catch {}
    return res.status(500).json({ error: 'Ошибка перевода средств' })
  }

  const senderNewBalance = db.prepare('SELECT balance FROM players WHERE id = ?').get(id).balance
  res.status(201).json({
    success: true,
    transferId,
    amountKopecks: amount,
    comment: cleanComment,
    balanceKopecks: senderNewBalance,
    message: `Успешно переведено ${(amount / 100).toLocaleString('ru-RU')} ₽ игроку ${recipient.nickname}!`
  })
}

app.post('/api/transfers', transferHandler)
app.post('/api/player/transfer', transferHandler)

// Player notifications: list transfers and alerts
app.get('/api/player/notifications', (req, res) => {
  const id = req.query.id || req.headers['x-player-id']
  const authToken = req.query.authToken || req.headers['x-auth-token']
  if (!id) {
    return res.status(400).json({ error: 'Missing player id' })
  }
  const player = db.prepare('SELECT id FROM players WHERE id = ?').get(id)
  if (!player) {
    return res.status(404).json({ error: 'Игрок не найден' })
  }

  const rows = db.prepare(`
    SELECT
      t.id,
      t.from_player_id AS fromPlayerId,
      t.to_player_id AS toPlayerId,
      p_from.nickname AS fromNickname,
      p_to.nickname AS toNickname,
      t.amount AS amountKopecks,
      t.comment,
      t.created_at AS createdAt
    FROM wallet_transfers t
    LEFT JOIN players p_from ON p_from.id = t.from_player_id
    LEFT JOIN players p_to ON p_to.id = t.to_player_id
    WHERE t.from_player_id = ? OR t.to_player_id = ?
    ORDER BY t.created_at DESC
    LIMIT 60
  `).all(id, id)

  res.json(rows.map(r => ({
    id: r.id,
    type: 'transfer',
    isIncoming: r.toPlayerId === id,
    fromPlayerId: r.fromPlayerId,
    fromNickname: r.fromNickname || 'Игрок',
    toPlayerId: r.toPlayerId,
    toNickname: r.toNickname || 'Игрок',
    amountKopecks: r.amountKopecks,
    amountRub: r.amountKopecks / 100,
    comment: r.comment || '',
    createdAt: r.createdAt
  })))
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
  const { min_version_code, latest_version_name, telegram_channel, telegram_url, update_message, force_update_enabled, econ_reset_at, admin_password, current_admin_password } = req.body
  if (admin_password !== undefined) {
    if (!current_admin_password || hashPassword(String(current_admin_password)) !== hashPassword(ADMIN_SECRET)) return res.status(400).json({ error: 'Неверный текущий пароль администратора' })
    if (String(admin_password).length < 4) return res.status(400).json({ error: 'Пароль должен быть не менее 4 символов' })
    ADMIN_SECRET = String(admin_password)
    setAppConfig('admin_secret', ADMIN_SECRET)
    return res.json({ success: true, message: 'Пароль администратора обновлён' })
  }
  if (min_version_code !== undefined) setAppConfig('min_version_code', min_version_code)
  if (latest_version_name !== undefined) setAppConfig('latest_version_name', latest_version_name)
  if (telegram_channel !== undefined) setAppConfig('telegram_channel', telegram_channel)
  if (telegram_url !== undefined) setAppConfig('telegram_url', telegram_url)
  if (update_message !== undefined) setAppConfig('update_message', update_message)
  if (force_update_enabled !== undefined) setAppConfig('force_update_enabled', force_update_enabled ? '1' : '0')
  if (econ_reset_at !== undefined) {
    const marker = Number(econ_reset_at) || Date.now()
    setAppConfig('econ_reset_at', String(marker))
    // Reset all players in DB: starter balance 7 500 ₽, empty inventory, level 1, 0 stats (wiping leaderboard)
    db.prepare(`
      UPDATE players SET
        balance = 750000,
        pending_bonus = 0,
        inventory_json = '[]',
        pending_inventory_json = NULL,
        level = 1,
        xp = 0,
        upgrades_count = 0,
        won_count = 0,
        biggest_win = 0,
        quests_json = '[]',
        quest_stats_json = '{}',
        economy_reset_at = ?
    `).run(marker)
    try { db.prepare('DELETE FROM wallet_transfers').run() } catch {}
    try { db.prepare('DELETE FROM wallet_transactions').run() } catch {}
    try { db.prepare('DELETE FROM promocode_redemptions').run() } catch {}

    db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
      'ADMIN_ECON_RESET',
      `Full economy & leaderboard reset for ALL players (balance=7500 RUB, inventory cleared, stats zeroed) marker=${marker}`,
      marker
    )
  }

  res.json({ success: true, message: 'Настройки версий успешно обновлены' })
})

// Direct endpoint to reset full economy and leaderboard across all players
app.post('/api/admin/economy/reset-all', requireAdmin, (req, res) => {
  const marker = Date.now()
  setAppConfig('econ_reset_at', String(marker))
  db.prepare(`
    UPDATE players SET
      balance = 750000,
      pending_bonus = 0,
      inventory_json = '[]',
      pending_inventory_json = NULL,
      level = 1,
      xp = 0,
      upgrades_count = 0,
      won_count = 0,
      biggest_win = 0,
      quests_json = '[]',
      quest_stats_json = '{}',
      economy_reset_at = ?
  `).run(marker)
  try { db.prepare('DELETE FROM wallet_transfers').run() } catch {}
  try { db.prepare('DELETE FROM wallet_transactions').run() } catch {}
  try { db.prepare('DELETE FROM promocode_redemptions').run() } catch {}

  db.prepare('INSERT INTO admin_logs (action, details, timestamp) VALUES (?, ?, ?)').run(
    'ADMIN_ECON_RESET',
    `Full economy & leaderboard reset for ALL players (balance=7500 RUB, inventory cleared, stats zeroed) marker=${marker}`,
    marker
  )
  res.json({ success: true, message: 'Экономика и лидерборд всех игроков успешно сброшены', marker })
})

// ----------------------------------------------------
// WEB ADMIN DASHBOARD (Browser-accessible at /admin)
// ----------------------------------------------------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'))
})

// ----------------------------------------------------
// WEB VERSION OF THE GAME (browser-accessible at /play/)
// ----------------------------------------------------
app.get('/play', (req, res, next) => (req.originalUrl === '/play' ? res.redirect(301, '/play/') : next()))
app.use('/play', express.static(path.join(__dirname, 'web'), { maxAge: '1h', index: 'index.html' }))

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[CS2 Upgrader Server] Running on http://0.0.0.0:${PORT}`)
  console.log(`[Admin Panel] Accessible at http://localhost:${PORT}/admin (Key: ${ADMIN_SECRET})`)
})
