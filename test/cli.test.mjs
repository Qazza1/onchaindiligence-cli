import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const here = dirname(fileURLToPath(import.meta.url))
const cli = join(here, '..', 'bin', 'cli.js')
const noNetwork = pathToFileURL(join(here, 'prevent-network.mjs')).href

function fixture(purpose = 'compliance-screening-result') {
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
    purpose,
    schema_version: 'onchaindiligence.attestation.v2',
  })
  const envelope = {
    data,
    attestation: {
      signed: true,
      schema_version: 'onchaindiligence.attestation.v2',
      issuer: 'https://api.onchaindiligence.com',
      purpose,
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

test('verify accepts every current generic OCD attestation artifact purpose offline', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const purposes = [
    'compliance-screening-result',
    'public-action-receipt',
    'erc20-allowance-action',
    'swap-action',
    'bridge-action',
    'staking-action',
  ]
  for (const purpose of purposes) {
    const { envelope, trust } = fixture(purpose)
    const envelopePath = join(dir, `${purpose}.json`)
    const trustPath = join(dir, `${purpose}-keys.json`)
    writeFileSync(envelopePath, JSON.stringify(envelope))
    writeFileSync(trustPath, JSON.stringify(trust))
    const result = await run(['verify', envelopePath, '--trust', trustPath, '--json'])
    assert.equal(result.code, 0, `${purpose}: ${result.stderr}`)
    assert.equal(JSON.parse(result.stdout).state, 'VALID')
  }
})

test('verify adapts the current Public Action Receipt wrapper without network access', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope, trust } = fixture('public-action-receipt')
  const receiptPath = join(dir, 'receipt.json')
  const trustPath = join(dir, 'keys.json')
  writeFileSync(receiptPath, JSON.stringify({
    schema: 'onchaindiligence.public-action-receipt.v1',
    receipt: envelope.data,
    proof: envelope.attestation,
  }))
  writeFileSync(trustPath, JSON.stringify(trust))
  const result = await run(['verify', receiptPath, '--trust', trustPath, '--json'])
  assert.equal(result.code, 0, result.stderr)
  assert.equal(JSON.parse(result.stdout).state, 'VALID')
})

test('verify recognizes portable bundles offline and preserves their distinct report fields', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-bundle-'))
  const corpus = join(here, '..', 'node_modules', '@onchaindiligence', 'agent-evidence', 'conformance')
  const bundle = JSON.parse(readFileSync(join(corpus, 'bundle-with-artifacts.json'), 'utf8'))
  const bundlePath = join(dir, 'bundle.json')
  const trustPath = join(dir, 'keys.json')
  writeFileSync(bundlePath, JSON.stringify(bundle))
  writeFileSync(trustPath, JSON.stringify({ keys: bundle.verification_material.keys }))

  const documented = await run(['verify', bundlePath, '--trust', trustPath])
  assert.equal(documented.code, 0, documented.stderr)
  assert.match(documented.stdout, /bundle integrity: VALID/)
  assert.match(documented.stdout, /artifact sha256:/)
  assert.match(documented.stdout, /insufficient_evidence:/)
  assert.match(documented.stdout, /limitation:/)

  const result = await run(['verify', bundlePath, '--trust', trustPath, '--json'])
  assert.equal(result.code, 0, result.stderr)
  const output = JSON.parse(result.stdout)
  assert.equal(output.bundle_integrity.state, 'VALID')
  assert.equal(output.state, 'VALID')
  assert.ok(Array.isArray(output.artifact_verifications))
  assert.ok(output.reconciliation)
  assert.ok(Array.isArray(output.limitations))

  for (const [name, expectedCode, expectedState] of [
    ['bundle-invalid-child.json', 3, 'INVALID'],
    ['bundle-unverifiable-child.json', 4, 'UNVERIFIABLE'],
  ]) {
    const candidate = JSON.parse(readFileSync(join(corpus, name), 'utf8'))
    writeFileSync(bundlePath, JSON.stringify(candidate))
    writeFileSync(trustPath, JSON.stringify({ keys: candidate.verification_material.keys }))
    const candidateResult = await run(['verify', bundlePath, '--trust', trustPath, '--json'])
    assert.equal(candidateResult.code, expectedCode, candidateResult.stderr)
    assert.equal(JSON.parse(candidateResult.stdout).state, expectedState)
  }
})

test('--version reads installed package metadata', async () => {
  const result = await run(['--version'])
  assert.equal(result.code, 0, result.stderr)
  assert.equal(result.stdout.trim(), '@onchaindiligence/cli 0.4.0')
})

test('malformed or ambiguous trust material is rejected without online fallback', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-'))
  const { envelope, trust } = fixture()
  const envelopePath = join(dir, 'attestation.json')
  writeFileSync(envelopePath, JSON.stringify(envelope))
  const cases = [
    { name: 'wrong algorithm', material: { ...trust, keys: [{ ...trust.keys[0], algorithm: 'rsa' }] } },
    { name: 'duplicate key id', material: { ...trust, keys: [trust.keys[0], { ...trust.keys[0] }] } },
  ]
  for (const item of cases) {
    const trustPath = join(dir, `${item.name}.json`)
    writeFileSync(trustPath, JSON.stringify(item.material))
    const result = await run(['verify', envelopePath, '--trust', trustPath, '--json'])
    assert.equal(result.code, 2, item.name)
    assert.match(result.stderr, /trust file is invalid/, item.name)
  }
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
