import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const here = dirname(fileURLToPath(import.meta.url))
const cli = join(here, '..', 'bin', 'cli.js')
const noNetwork = pathToFileURL(join(here, 'prevent-network.mjs')).href

function fixture() {
  const pair = generateKeyPairSync('ed25519')
  const der = pair.publicKey.export({ type: 'spki', format: 'der' })
  const keyId = `ed25519-${createHash('sha256').update(der).digest('base64url').slice(0, 16)}`
  const issuedAt = new Date(Date.now() - 1_000).toISOString()
  const data = { address: '0x0000000000000000000000000000000000000001', sanctioned: false }
  const input = JSON.stringify({
    data,
    issued_at: issuedAt,
    issuer: 'https://api.onchaindiligence.com',
    key_id: keyId,
    purpose: 'compliance-screening-result',
    schema_version: 'onchaindiligence.attestation.v2',
  })
  const envelope = {
    data,
    attestation: {
      signed: true,
      schema_version: 'onchaindiligence.attestation.v2',
      issuer: 'https://api.onchaindiligence.com',
      purpose: 'compliance-screening-result',
      issued_at: issuedAt,
      key_id: keyId,
      algorithm: 'ed25519',
      canonicalization: 'RFC8785',
      signature: sign(null, Buffer.from(input), pair.privateKey).toString('base64url'),
    },
  }
  const trust = {
    registry_version: 1,
    issuer: 'https://api.onchaindiligence.com',
    keys: [{
      key_id: keyId,
      algorithm: 'ed25519',
      public_key_pem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      status: 'active',
      valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: null,
      status_changed_at: new Date(Date.now() - 60_000).toISOString(),
    }],
  }
  return { envelope, trust }
}

function run(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], {
      env: { ...process.env, NODE_OPTIONS: `--import=${noNetwork}`, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

test('verify is genuinely offline and returns VALID with caller trust', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope, trust } = fixture()
  const envelopePath = join(dir, 'attestation.json')
  const trustPath = join(dir, 'keys.json')
  writeFileSync(envelopePath, JSON.stringify(envelope))
  writeFileSync(trustPath, JSON.stringify(trust))

  const result = await run(['verify', envelopePath, '--trust', trustPath, '--json'])
  assert.equal(result.code, 0, result.stderr)
  const output = JSON.parse(result.stdout)
  assert.equal(output.state, 'VALID')
  assert.equal(output.components.signature.state, 'PASS')
})

test('verify returns distinct INVALID and UNVERIFIABLE exit codes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope, trust } = fixture()
  const envelopePath = join(dir, 'attestation.json')
  const trustPath = join(dir, 'keys.json')
  const emptyTrustPath = join(dir, 'unknown-keys.json')
  envelope.data.sanctioned = true
  writeFileSync(envelopePath, JSON.stringify(envelope))
  writeFileSync(trustPath, JSON.stringify(trust))
  writeFileSync(emptyTrustPath, JSON.stringify({ keys: [] }))

  const invalid = await run(['verify', envelopePath, '--trust', trustPath, '--json'])
  assert.equal(invalid.code, 3)
  assert.equal(JSON.parse(invalid.stdout).state, 'INVALID')

  const unverifiable = await run(['verify', envelopePath, '--trust', emptyTrustPath, '--json'])
  assert.equal(unverifiable.code, 4)
  assert.equal(JSON.parse(unverifiable.stdout).state, 'UNVERIFIABLE')
})

test('verify never silently falls back to online key discovery', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope } = fixture()
  const envelopePath = join(dir, 'attestation.json')
  writeFileSync(envelopePath, JSON.stringify(envelope))
  const result = await run(['verify', envelopePath])
  assert.equal(result.code, 2)
  assert.match(result.stderr, /requires --trust/)
})

test('--fetch-keys is a separate explicit online registry flow', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope, trust } = fixture()
  const envelopePath = join(dir, 'attestation.json')
  writeFileSync(envelopePath, JSON.stringify(envelope))

  const server = createServer((request, response) => {
    const key = trust.keys[0]
    if (request.url === `/.well-known/attestation-keys/${key.key_id}`) {
      response.writeHead(200, { 'Content-Type': 'application/json' })
      response.end(JSON.stringify({ key }))
      return
    }
    response.writeHead(404).end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())
  const address = server.address()
  const baseUrl = `http://127.0.0.1:${address.port}`

  const result = await run(['verify', envelopePath, '--fetch-keys', '--json'], {
    env: { NODE_OPTIONS: '', OCD_BASE_URL: baseUrl },
  })
  assert.equal(result.code, 0, result.stderr)
  assert.equal(JSON.parse(result.stdout).state, 'VALID')
})
