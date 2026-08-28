#!/usr/bin/env node
/**
 * @onchaindiligence/cli
 * ---------------------
 * A thin command-line wrapper over @onchaindiligence/sdk.
 *
 * Design principle (honest by construction):
 *   - FREE commands require no payer key. Verification additionally requires
 *     caller-selected trust material (or an explicit online lookup flag).
 *   - PAID commands (screen, screen-name, company, us-company, diligence,
 *     anchor) each settle a real per-call payment, so they need a funded payer
 *     key in the PAYER_KEY env var. If it's missing, we fail with a clear,
 *     actionable message rather than a cryptic stack trace.
 *
 * Nothing here reimplements compliance logic — it's a presentation layer over
 * the published SDK, so the CLI and the SDK can never drift.
 */

import {
  OnchainDiligence,
  parseJsonNoDuplicateKeys,
  verifyAttestationOffline,
  verifyAttestationOnline,
} from '@onchaindiligence/sdk'
import { readFileSync } from 'node:fs'

const VERSION = '0.2.0'
const BASE_URL = process.env.OCD_BASE_URL || undefined // SDK defaults to production

// ---- tiny ANSI helpers (no dependency) ----
const isTTY = process.stdout.isTTY
const c = (code, s) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s)
const bold = (s) => c('1', s)
const red = (s) => c('31', s)
const green = (s) => c('32', s)
const yellow = (s) => c('33', s)
const dim = (s) => c('2', s)

function out(obj) {
  // Pretty by default; --json prints raw for piping.
  if (flags.json) {
    process.stdout.write(JSON.stringify(obj, null, 2) + '\n')
  } else {
    process.stdout.write(JSON.stringify(obj, null, 2) + '\n')
  }
}

function die(msg, code = 1) {
  process.stderr.write(red('error: ') + msg + '\n')
  process.exit(code)
}

// ---- arg parsing (minimal, no dependency) ----
const argv = process.argv.slice(2)
const flags = { json: false, fetchKeys: false, trust: undefined }
const positional = []
for (let i = 0; i < argv.length; i++) {
  const a = argv[i]
  if (a === '--json') flags.json = true
  else if (a === '--help' || a === '-h') flags.help = true
  else if (a === '--version' || a === '-v') flags.version = true
  else if (a.startsWith('--threshold=')) flags.threshold = Number(a.split('=')[1])
  else if (a === '--fetch-keys') flags.fetchKeys = true
  else if (a.startsWith('--trust=')) flags.trust = a.slice('--trust='.length)
  else if (a === '--trust') {
    const value = argv[++i]
    if (!value || value.startsWith('--')) die('--trust requires a path', 2)
    flags.trust = value
  }
  else if (a.startsWith('--')) die(`unknown flag: ${a}`, 2)
  else positional.push(a)
}

const command = positional[0]
const arg1 = positional[1]

const HELP = `${bold('onchaindiligence')} — compliance checks from the command line

${bold('Usage')}
  npx @onchaindiligence/cli <command> [args] [--json]

${bold('Free commands')} ${dim('(no key required)')}
  verify <file.json>        Verify offline with --trust <keys.json>
  health                    Show API + upstream status
  anchored <signature>      Check if an attestation is anchored on Tempo

${bold('Paid commands')} ${dim('(require PAYER_KEY env var)')}
  screen <address>          Sanctions-screen a wallet address
  screen-name <name>        Screen a name against the OFAC SDN list
  company <number>          Verify a UK company (Companies House)
  us-company <query>        Verify a US public company (SEC EDGAR)
  diligence <addr> <num>    Wallet + company in one call
  anchor <file.json>        Anchor a complete signed attestation envelope

${bold('Flags')}
  --json                    Raw JSON output (for piping)
  --trust <keys.json>       Caller-trusted key registry for offline verify
  --fetch-keys              Explicitly fetch and trust the issuer registry
  --threshold=N             Name-screen match threshold (screen-name only)
  -h, --help                Show this help
  -v, --version             Show version

${bold('Paying for checks')}
  Paid commands settle a real per-call payment on-chain. Set a funded payer key:
    ${dim('export PAYER_KEY=0x…   # a viem private key with funds on the payment rail')}
  Free commands need no payer key; verify requires --trust or --fetch-keys.

  Docs: https://onchaindiligence.com/docs`

// ---- client factory: only build a paid client when a key exists ----
function paidClient() {
  const key = process.env.PAYER_KEY
  if (!key) {
    die(
      'this command settles a payment and needs a funded payer key.\n' +
        '  Set one with:  ' + dim('export PAYER_KEY=0x…') + '\n' +
        '  Free commands (verify, health, anchored) need no key.\n' +
        '  See https://onchaindiligence.com/docs for funding the payer.'
    )
  }
  // Import viem lazily so free commands don't pay the import cost / dependency.
  return import('viem/accounts')
    .then(({ privateKeyToAccount }) => {
      let account
      try {
        account = privateKeyToAccount(key.startsWith('0x') ? key : `0x${key}`)
      } catch (e) {
        die('PAYER_KEY is not a valid private key. Expected a 0x-prefixed hex key.')
      }
      return new OnchainDiligence({ account, baseUrl: BASE_URL })
    })
    .catch((e) => {
      die(
        'could not load the payment layer (viem/mppx). Make sure the CLI is installed ' +
          'with its dependencies, or run via `npx @onchaindiligence/cli`.\n  ' + dim(String(e && e.message || e))
      )
    })
}

// A free client needs no account for verify/health/anchored, but the SDK
// constructor requires an account field. We pass a throwaway inert object only
// used for shape — free methods never sign. To stay honest and avoid a fake
// account, we call the free HTTP endpoints directly for health, and use the
// SDK's account-free verify path for verify. anchored also hits a free GET.
function readTextFile(file, label = 'file') {
  try {
    return readFileSync(file, 'utf8')
  } catch (e) {
    die(`could not read ${label}: ${file}`)
  }
}

function readJsonFile(file, label = 'file') {
  const raw = readTextFile(file, label)
  try {
    return parseJsonNoDuplicateKeys(raw)
  } catch (e) {
    die(`${file} is not valid unambiguous JSON: ${e && e.message ? e.message : e}`)
  }
}

function normalizeTrustMaterial(value) {
  if (Array.isArray(value)) return { keys: value }
  if (value && typeof value === 'object' && Array.isArray(value.keys)) return value
  die('trust material must be a registry object with a "keys" array (or the array itself)', 2)
}

async function freeVerify(file) {
  if (flags.trust && flags.fetchKeys) {
    die('choose either --trust for offline verification or --fetch-keys for explicit online discovery', 2)
  }
  if (!flags.trust && !flags.fetchKeys) {
    die('verify requires --trust <keys.json>; use --fetch-keys only when online registry trust is intentional', 2)
  }

  const raw = readTextFile(file)
  let res
  try {
    if (flags.trust) {
      const trust = normalizeTrustMaterial(readJsonFile(flags.trust, 'trust file'))
      res = await verifyAttestationOffline(raw, trust)
    } else {
      res = await verifyAttestationOnline(raw, {
        baseUrl: BASE_URL,
        trustRegistry: true,
      })
    }
  } catch (e) {
    die('verification could not run: ' + (e && e.message ? e.message : e))
  }
  if (flags.json) out(res)
  else {
    const marker = res.state === 'VALID' ? green('✓ VALID') : res.state === 'INVALID' ? red('✗ INVALID') : yellow('? UNVERIFIABLE')
    process.stdout.write(`${marker}  ${res.reason}\n`)
    process.stdout.write(dim(`  key: ${res.keyId || 'unresolved'}  code: ${res.code}\n`))
  }
  process.exit(res.state === 'VALID' ? 0 : res.state === 'INVALID' ? 3 : 4)
}

function readAnchorEnvelope(file) {
  const envelope = readJsonFile(file)
  if (!envelope || typeof envelope !== 'object' || !Object.hasOwn(envelope, 'data') || !envelope.attestation) {
    die('anchor requires a file containing the complete signed response envelope', 2)
  }
  return envelope
}

async function freeHealth() {
  const base = (BASE_URL || 'https://api.onchaindiligence.com').replace(/\/$/, '')
  let res
  try {
    res = await fetch(base + '/health')
  } catch (e) {
    die('could not reach the API: ' + (e && e.message ? e.message : e))
  }
  const d = await res.json()
  if (flags.json) return out(d)
  const ok = d.status === 'ok'
  process.stdout.write((ok ? green('● operational') : yellow('● ' + d.status)) + '\n')
  for (const [k, v] of Object.entries(d.upstreams || {})) {
    const good = v === 'reachable'
    process.stdout.write(`  ${good ? green('✓') : red('✗')} ${k}: ${v}\n`)
  }
  process.stdout.write(dim(`  signing: ${d.attestation}\n`))
  process.exit(ok ? 0 : 2)
}

async function freeAnchored(sig) {
  if (!sig) die('usage: anchored <signature>')
  const od = new OnchainDiligence({ account: {}, baseUrl: BASE_URL })
  let d
  try {
    d = await od.anchored(sig)
  } catch (e) {
    die('could not check anchor status: ' + (e && e.message ? e.message : e))
  }
  if (flags.json) return out(d)
  process.stdout.write(
    (d.anchored ? green('✓ anchored') : dim('○ not anchored')) +
      (d.anchored_at ? dim(`  at ${d.anchored_at}`) : '') +
      dim(`  (${d.chain})\n`)
  )
  process.exit(0)
}

// ---- paid command runner ----
async function runPaid(fn) {
  const od = await paidClient()
  let result
  try {
    result = await fn(od)
  } catch (e) {
    const status = e && e.status ? ` [${e.status}]` : ''
    die('request failed' + status + ': ' + (e && e.message ? e.message : e))
  }
  out(result)
  process.exit(0)
}

// ---- dispatch ----
async function main() {
  if (flags.version) { process.stdout.write('@onchaindiligence/cli ' + VERSION + '\n'); return }
  if (!command || flags.help) { process.stdout.write(HELP + '\n'); return }

  switch (command) {
    // free
    case 'verify': return freeVerify(arg1 || die('usage: verify <file.json>'))
    case 'health': return freeHealth()
    case 'anchored': return freeAnchored(arg1)

    // paid
    case 'screen':
      if (!arg1) die('usage: screen <address>')
      return runPaid((od) => od.screen(arg1))
    case 'screen-name':
      if (!arg1) die('usage: screen-name <name>')
      return runPaid((od) => od.screenName(arg1, flags.threshold ? { threshold: flags.threshold } : undefined))
    case 'company':
      if (!arg1) die('usage: company <number>')
      return runPaid((od) => od.verifyCompany(arg1))
    case 'us-company':
      if (!arg1) die('usage: us-company <query>')
      return runPaid((od) => od.verifyUSCompany(arg1))
    case 'diligence': {
      const wallet = arg1
      const company = positional[2]
      if (!wallet && !company) die('usage: diligence <address> <company-number>')
      return runPaid((od) => od.diligence({ wallet, company }))
    }
    case 'anchor': {
      if (!arg1) die('usage: anchor <file.json>', 2)
      const envelope = readAnchorEnvelope(arg1)
      return runPaid((od) => od.anchor(envelope))
    }

    default:
      die(`unknown command: ${command}\n  Run ${dim('onchaindiligence --help')} for usage.`)
  }
}

main().catch((e) => die(e && e.message ? e.message : String(e)))
