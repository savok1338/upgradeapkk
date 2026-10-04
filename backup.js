// Keeps the SQLite DB safe on Render's ephemeral free tier (no persistent disk
// on the free plan): on boot the DB file is restored from a GitHub backup, and
// snapshots are pushed on a timer and on shutdown (Render SIGTERMs the old
// container before recreating it, so deploys lose at most the timer interval).
//
// Env vars:
//   GH_BACKUP_TOKEN          GitHub token with Contents RW (enables the feature)
//   GH_BACKUP_REPO           default: savok1338/upgradeapkk
//   GH_BACKUP_BRANCH         default: db-backup (pushes here never redeploy Render)
//   GH_BACKUP_FILE           default: upgrader.db
//   GH_BACKUP_INTERVAL_MIN   default: 10

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

const TOKEN = process.env.GH_BACKUP_TOKEN || ''
const REPO = process.env.GH_BACKUP_REPO || 'savok1338/upgradeapkk'
const BRANCH = process.env.GH_BACKUP_BRANCH || 'db-backup'
const FILE_PATH = process.env.GH_BACKUP_FILE || 'upgrader.db'
const INTERVAL_MIN = Number(process.env.GH_BACKUP_INTERVAL_MIN || 10)

const API = 'https://api.github.com'

function ghFetch(url, options = {}, timeoutMs = 20000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return fetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'upgrader-server',
        ...(options.headers || {}),
      },
      signal: controller.signal,
    })
  } finally {
    clearTimeout(timer)
  }
}

async function getBackupMeta() {
  const res = await ghFetch(`${API}/repos/${REPO}/contents/${FILE_PATH}?ref=${BRANCH}`)
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`GitHub GET meta ${res.status}`)
  return res.json()
}

async function downloadBackup() {
  const res = await ghFetch(`${API}/repos/${REPO}/contents/${FILE_PATH}?ref=${BRANCH}`, {
    headers: { Accept: 'application/vnd.github.raw' },
  })
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`GitHub GET raw ${res.status}`)
  return Buffer.from(await res.arrayBuffer())
}

async function ensureBranch() {
  const ref = await ghFetch(`${API}/repos/${REPO}/git/ref/heads/${BRANCH}`)
  if (ref.ok) return
  if (ref.status !== 404) throw new Error(`GitHub ref ${ref.status}`)
  const repoInfo = await (await ghFetch(`${API}/repos/${REPO}`)).json()
  const def = repoInfo.default_branch || 'main'
  const base = await ghFetch(`${API}/repos/${REPO}/git/ref/heads/${def}`)
  if (!base.ok) throw new Error(`GitHub base ref ${base.status}`)
  const baseSha = (await base.json()).object.sha
  const created = await ghFetch(`${API}/repos/${REPO}/git/refs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref: `refs/heads/${BRANCH}`, sha: baseSha }),
  })
  // 422 = already exists (race) — fine
  if (!created.ok && created.status !== 422) throw new Error(`GitHub create ref ${created.status}`)
}

// Called before the main DatabaseSync connection opens.
export async function restoreFromBackup(dbPath) {
  const localExists = fs.existsSync(dbPath)
  if (localExists) {
    let count = 0
    let probe
    try {
      probe = new DatabaseSync(dbPath)
      count = probe.prepare('SELECT COUNT(*) as c FROM players').get()?.c || 0
    } catch {
      count = 0
    } finally {
      try { probe?.close() } catch {}
    }
    if (count > 0) {
      console.log('[backup] local DB has data — restore skipped')
      return
    }
  }

  const buf = await downloadBackup()
  if (!buf) {
    console.log('[backup] no GitHub backup yet — starting fresh')
    return
  }
  fs.writeFileSync(dbPath, buf)
  console.log(`[backup] restored DB from GitHub (${(buf.length / 1024).toFixed(1)} KB)`)
}

let lastUploadedHash = ''
let uploading = false

async function backupNow(db) {
  if (uploading) return
  uploading = true
  const tmp = path.join(os.tmpdir(), `upgrader-snap-${process.pid}-${Date.now()}.db`)
  try {
    const players = db.prepare('SELECT COUNT(*) as c FROM players').get()?.c || 0
    if (players === 0) {
      // never overwrite a good backup with a fresh empty DB
      console.log('[backup] skip: no players yet')
      return
    }

    db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`)
    const buf = fs.readFileSync(tmp)
    const hash = crypto.createHash('sha1').update(buf).digest('hex')
    if (hash === lastUploadedHash) {
      console.log('[backup] skip: unchanged since last snapshot')
      return
    }

    const meta = await getBackupMeta()
    await ensureBranch()
    const put = await ghFetch(`${API}/repos/${REPO}/contents/${FILE_PATH}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `db backup ${new Date().toISOString()}`,
        content: buf.toString('base64'),
        branch: BRANCH,
        ...(meta?.sha ? { sha: meta.sha } : {}),
      }),
    })
    if (!put.ok) {
      const text = (await put.text()).slice(0, 200)
      throw new Error(`GitHub PUT ${put.status}: ${text}`)
    }
    lastUploadedHash = hash
    console.log(`[backup] snapshot uploaded (${(buf.length / 1024).toFixed(1)} KB, ${players} players)`)
  } catch (e) {
    console.error('[backup] upload failed:', e?.message || e)
  } finally {
    try { fs.unlinkSync(tmp) } catch {}
    uploading = false
  }
}

export function startBackupScheduler(db) {
  if (!TOKEN) return
  console.log(`[backup] enabled: repo=${REPO} branch=${BRANCH} every ${INTERVAL_MIN} min`)
  setInterval(() => backupNow(db), Math.max(1, INTERVAL_MIN) * 60 * 1000)

  let shuttingDown = false
  const shutdown = () => {
    if (shuttingDown) return
    shuttingDown = true
    console.log('[backup] shutdown — pushing final snapshot')
    backupNow(db).finally(() => process.exit(0))
    setTimeout(() => process.exit(0), 8000)
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
