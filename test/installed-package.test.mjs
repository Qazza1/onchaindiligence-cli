/** D4.1: prove the packed npm artifact verifies offline without this checkout. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync, rmSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options })
    let stdout = '', stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

function runNpm(args, options = {}) {
  if (process.platform !== 'win32') return run('npm', args, options)
  // Every argument used by this test is generated locally and contains no
  // spaces; leaving them unquoted avoids cmd.exe forwarding quote marks as
  // literal npm command characters on Windows.
  const command = ['npm.cmd', ...args.map(String)].join(' ')
  return run(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', command], options)
}

function fixture() {
  const pair = generateKeyPairSync('ed25519')
  const der = pair.publicKey.export({ type: 'spki', format: 'der' })
  const keyId = `ed25519-${createHash('sha256').update(der).digest('base64url').slice(0, 16)}`
  const issuedAt = new Date(Date.now() - 1_000).toISOString()
  const data = { action: 'receipt-portability-check' }
  const input = JSON.stringify({ data, issued_at: issuedAt, issuer: 'https://api.onchaindiligence.com', key_id: keyId, purpose: 'public-action-receipt', schema_version: 'onchaindiligence.attestation.v2' })
  return {
    envelope: { data, attestation: { signed: true, schema_version: 'onchaindiligence.attestation.v2', issuer: 'https://api.onchaindiligence.com', purpose: 'public-action-receipt', issued_at: issuedAt, key_id: keyId, algorithm: 'ed25519', canonicalization: 'RFC8785', signature: sign(null, Buffer.from(input), pair.privateKey).toString('base64url') } },
    trust: { keys: [{ key_id: keyId, algorithm: 'ed25519', public_key_pem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), status: 'active', valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: null }] },
  }
}

test('packed installed CLI reports its manifest version and verifies a receipt with zero network access', async (t) => {
  const packed = await runNpm(['pack', '--json'], { cwd: root, env: process.env })
  assert.equal(packed.code, 0, `${packed.stderr}\n${packed.stdout}`)
  const tarball = join(root, JSON.parse(packed.stdout)[0].filename)
  t.after(() => unlinkSync(tarball))

  const dir = mkdtempSync(join(tmpdir(), 'ocd-cli-installed-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const localDependencies = [
    process.env.OCD_AGENT_EVIDENCE_TARBALL,
    process.env.OCD_SDK_TARBALL,
  ].filter(Boolean)
  // Installing a packed package may resolve its normal transitive runtime
  // dependencies. The following CLI processes, not npm installation, are the
  // zero-network verification boundary and are explicitly blocked below.
  const install = await runNpm(['install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', ...localDependencies, tarball], { cwd: dir, env: process.env })
  assert.equal(install.code, 0, install.stderr)

  const { envelope, trust } = fixture()
  const artifactPath = join(dir, 'artifact.json')
  const trustPath = join(dir, 'keys.json')
  const hookPath = join(dir, 'block-network.mjs')
  writeFileSync(artifactPath, JSON.stringify(envelope))
  writeFileSync(trustPath, JSON.stringify(trust))
  writeFileSync(hookPath, "globalThis.fetch = async () => { throw new Error('offline verification attempted network access') }\n")
  const installedCli = join(dir, 'node_modules', '@onchaindiligence', 'cli', 'bin', 'cli.js')
  const version = await run(process.execPath, [installedCli, '--version'], { cwd: dir })
  assert.equal(version.code, 0, version.stderr)
  assert.equal(version.stdout.trim(), '@onchaindiligence/cli 0.4.0')
  const verified = await run(process.execPath, [installedCli, 'verify', artifactPath, '--trust', trustPath, '--json'], { cwd: dir, env: { NODE_OPTIONS: `--import=${new URL(`file:///${hookPath.replace(/\\/g, '/')}`).href}` } })
  assert.equal(verified.code, 0, verified.stderr)
  assert.equal(JSON.parse(verified.stdout).state, 'VALID')

  const corpus = join(root, 'node_modules', '@onchaindiligence', 'agent-evidence', 'conformance')
  const bundle = JSON.parse(readFileSync(join(corpus, 'bundle-with-artifacts.json'), 'utf8'))
  const bundlePath = join(dir, 'bundle.json')
  const bundleTrustPath = join(dir, 'bundle-keys.json')
  writeFileSync(bundlePath, JSON.stringify(bundle))
  writeFileSync(bundleTrustPath, JSON.stringify({ keys: bundle.verification_material.keys }))
  const bundleVerified = await run(process.execPath, [installedCli, 'verify', bundlePath, '--trust', bundleTrustPath, '--json'], { cwd: dir, env: { NODE_OPTIONS: `--import=${new URL(`file:///${hookPath.replace(/\\/g, '/')}`).href}` } })
  assert.equal(bundleVerified.code, 0, bundleVerified.stderr)
  const report = JSON.parse(bundleVerified.stdout)
  assert.equal(report.state, 'VALID')
  assert.equal(report.bundle_integrity.state, 'VALID')
  assert.ok(Array.isArray(report.artifact_verifications))
  assert.ok(report.reconciliation)
  assert.ok(Array.isArray(report.limitations))
})
