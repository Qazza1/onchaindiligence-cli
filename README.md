# @onchaindiligence/cli

Compliance checks from the command line — a thin wrapper over [`@onchaindiligence/sdk`](https://www.npmjs.com/package/@onchaindiligence/sdk).

Screen wallets, names, and companies, and verify signed attestations offline
against trust material you control.

```bash
# no install needed — run it directly
npx @onchaindiligence/cli --help
```

## Free commands (no key)

These need nothing but Node 18+. Great for CI and quick checks.

```bash
# Genuinely offline: no account and no network
npx @onchaindiligence/cli verify result.json --trust keys.json

# Optional explicit online discovery (not the default)
npx @onchaindiligence/cli verify result.json --fetch-keys

# API + upstream status
npx @onchaindiligence/cli health

# Is an attestation anchored on Tempo?
npx @onchaindiligence/cli anchored <signature>
```

`verify` exits `0` for `VALID`, `3` for `INVALID`, and `4` for
`UNVERIFIABLE`. Usage errors exit `2`. With `--json`, the component-aware result
is machine readable.

## Paid commands (need a payer key)

Each of these settles a real per-call payment on-chain, so they need a funded payer key in `PAYER_KEY`:

```bash
export PAYER_KEY=0x…   # a viem private key funded on the payment rail

npx @onchaindiligence/cli screen 0x7f268357A8c2552623316e2562D90e642bB538E5
npx @onchaindiligence/cli screen-name "Vladimir Putin"
npx @onchaindiligence/cli company 00000006
npx @onchaindiligence/cli us-company AAPL
npx @onchaindiligence/cli diligence 0x7f26… 00000006
npx @onchaindiligence/cli anchor result.json
```

If `PAYER_KEY` isn't set, paid commands stop with a clear message instead of failing mid-request.

## Flags

| Flag | Effect |
|------|--------|
| `--json` | Raw JSON output, for piping |
| `--trust <keys.json>` | Caller-trusted registry for zero-network verification |
| `--fetch-keys` | Explicitly fetch and trust the configured issuer registry |
| `--threshold=N` | Name-screen match threshold (`screen-name` only) |
| `-h`, `--help` | Usage |
| `-v`, `--version` | Version |

## Install globally (optional)

```bash
npm install -g @onchaindiligence/cli
onchaindiligence health      # or the short alias:  ocd health
```

## Notes

- Output is JSON by default so results pipe cleanly into `jq` or a file.
- `OCD_BASE_URL` overrides the API base (defaults to production).
- An attestation signature authenticates the signer's timestamp assertion; only
  a separately verified anchor establishes an external time bound.
- Verification uses the SDK's shared tri-state verifier and does not require a
  payer account.

## License

MIT
