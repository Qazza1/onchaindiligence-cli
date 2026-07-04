# @onchaindiligence/cli

Compliance checks from the command line — a thin wrapper over [`@onchaindiligence/sdk`](https://www.npmjs.com/package/@onchaindiligence/sdk).

Screen wallets, names, and companies, and **verify signed attestations locally with no key required**.

```bash
# no install needed — run it directly
npx @onchaindiligence/cli --help
```

## Free commands (no key)

These need nothing but Node 18+. Great for CI and quick checks.

```bash
# Verify a signed attestation locally (Ed25519, against the published key)
npx @onchaindiligence/cli verify result.json

# API + upstream status
npx @onchaindiligence/cli health

# Is an attestation anchored on Tempo?
npx @onchaindiligence/cli anchored <signature>
```

`verify` exits `0` if valid, `3` if the signature doesn't verify, `2` if the response was unsigned — so it drops straight into a CI step.

## Paid commands (need a payer key)

Each of these settles a real per-call payment on-chain, so they need a funded payer key in `PAYER_KEY`:

```bash
export PAYER_KEY=0x…   # a viem private key funded on the payment rail

npx @onchaindiligence/cli screen 0x7f268357A8c2552623316e2562D90e642bB538E5
npx @onchaindiligence/cli screen-name "Vladimir Putin"
npx @onchaindiligence/cli company 00000006
npx @onchaindiligence/cli us-company AAPL
npx @onchaindiligence/cli diligence 0x7f26… 00000006
npx @onchaindiligence/cli anchor <signature>
```

If `PAYER_KEY` isn't set, paid commands stop with a clear message instead of failing mid-request.

## Flags

| Flag | Effect |
|------|--------|
| `--json` | Raw JSON output, for piping |
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
- This CLI adds no compliance logic of its own — it's a presentation layer over the SDK, so the two never drift.

## License

MIT
