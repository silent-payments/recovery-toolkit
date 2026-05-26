# sp-recover-toolkit — BIP-352 silent payment recovery toolkit

Three scripts that together recover BIP-352 silent-payment funds when the
wallet that produced them (e.g. an older Cake Wallet build) used a
non-standard derivation path and can no longer spend them.

The work is split so the user controls how much private-key material each
step sees. The seed is only ever handled by `sp_derive`; the network is
only ever touched by `sp_scan`; signing only ever happens in `sp_sign`.

```
sp_derive   mnemonic           ->  scan_key, spend_priv, spend_pub
sp_scan     scan_key + pub    ->  history, unspent utxos, fee estimate
sp_sign     spend_priv + utxos ->  signed taproot sweep transaction (hex)
```

`sp_sign` does not broadcast. Relay the hex via `mempool.space/tx/push`,
a wallet, or your own node.


## Files

```
sp_crypto.py   pure crypto: mnemonic, BIP-32, BIP-352, bech32m. No I/O.
sp_derive.py   the only script that takes a mnemonic. No network.
sp_scan.py     speaks Electrum JSON-RPC over TLS to a Frigate server.
sp_sign.py     builds and signs a taproot sweep tx. No network.
test_sp.py     unit + integration tests (45, standard-library unittest).
requirements.txt pinned + hashed deps for `pip install --require-hashes`.
```


## Install

Requires Python 3.9+ and two pinned third-party packages (`coincurve`,
`python-bitcointx`). Recommended:

```
pipx install .
```

For hash-verified installs (preferred for a recovery tool):

```
pip install --require-hashes -r requirements.txt
pip install --no-deps .
```

Either gives you `sp_derive`, `sp_scan`, `sp_sign` on PATH. You can also
run the source files directly from the checkout.


## Usage

There are two equivalent ways to get JSON out of `sp_derive` and
`sp_scan`: pipe it straight into the next stage, or save it with the
`-o` / `--output` flag and rerun later. Pick one per stage — don't
redirect with `>` and also pass `-o`.

  - **Piping (`|`)**: nothing touches disk; the next stage reads JSON
    from stdin. Best for the one-shot pipeline.
  - **`-o <file>`**: writes the JSON to `<file>` instead of stdout.
    `sp_derive -o` creates the file with mode 0600 because it contains
    `spend_priv`; `sp_scan -o` does the same when `spend_priv` was piped
    through from `sp_derive`.

Either way, status and prompts go to stderr / `/dev/tty`.

### One-shot pipeline

```
sp_derive --sp-address sp1qq... | sp_scan | sp_sign bc1p...
```

### Staged invocation

If you don't want every script to see every value, run them
independently. Each accepts the values it needs on the CLI and reads any
non-key fields from a JSON file or stdin.

```
# 1. derive — never touches the network. --no-echo hides the seed.
#    -o writes keys.json with mode 0600 (contains spend_priv).
sp_derive --sp-address sp1qq... --no-echo -o keys.json

# 2. scan — accepts only the keys it actually uses. --start defaults to
#    taproot activation (block 709632); pass an explicit value to widen
#    or narrow the window.
sp_scan \
    --scan-key $(jq -r .scan_key keys.json) \
    --spend-pub $(jq -r .spend_pub keys.json) \
    -o scanned.json

# 3. sign — accepts only spend_priv + the scan output. No network.
sp_sign \
    --utxos scanned.json \
    --spend-priv $(jq -r .spend_priv keys.json) \
    --feerate 8 \
    bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
```

Note: keys passed via `$(jq ...)` end up in argv and are visible to other
local users via `ps`. The pipe form avoids this.

Run `<script> --help` for the full flag reference. The module docstrings
in each `.py` file document JSON shapes and edge cases.


## Audit boundary

What each file can do is bounded by what it imports. `sp_crypto`,
`sp_derive`, and `sp_sign` import no network modules — only `sp_scan`
opens a socket, and only to `--server` (default `frigate.2140.dev:50002`,
TLS).

Sent to Frigate, per its protocol:

  - `scan_key` + `spend_pub` hex on the silent-payments subscribe RPC
  - scripthashes derived from your `D` output keys
  - the integer 6 on the fee-estimate RPC

Never leaves the machine: mnemonic, seed, `spend_priv`, destination
address, signed transaction.

TLS uses `ssl.create_default_context()` (system trust store, no pinning).
If you want to defend against a valid-but-malicious cert for
`frigate.2140.dev`, run your own Frigate and pass `--server`.


## Failure modes

Scripts abort with a printed reason rather than producing partial output:

  - `sp_derive`: `ABORT: this seed does not derive --sp-address at any
    candidate path` — seed wrong, address wrong, or path not in
    `sp_crypto.CANDIDATE_PATHS`. No partial keys are printed.

  - `sp_scan`: `frigate closed the connection` — re-run; persistent
    failures usually mean the silent-payments backend is unhappy.

  - `sp_sign`: `ABORT: <txid>:<vout> spend_priv does not match
    scriptPubKey` — wrong key, swapped scan/spend, or `scanned.json` from
    a different SP address.

  - `sp_sign`: `no fee rate available; pass --feerate <sat/vB>` — the
    scan's estimate was -1/missing. The script never silently defaults.

  - `sp_sign`: `sweep amount below dust` — total in minus fee is under
    330 sat; cannot be relayed.


## Testing

```
python3 -m unittest test_sp -v
```

45 tests: bech32m + SP address round-trip, BIP-340 tagged-hash, BIP-352
test vectors (k=0 receiving cases), BIP-32 test vector 1, Electrum
mnemonic normalization + PBKDF2, scripthash, vsize estimation,
FrigateClient request/response handling, fee-rate conversion, and an
end-to-end `build_and_sign` that re-parses the signed hex, recomputes
the BIP-341 sighash, and schnorr-verifies each witness against the
input's x-only output key.


## Known limitations

  - Only `k = 0` outputs are derived per scan entry. Transactions paying
    multiple SP outputs to the same recipient will only have their k=0
    output recovered. Not a problem for the Cake Wallet recovery case as
    observed; relax by iterating `k` in `sp_scan.run_scan`.

  - Mainnet only. `sp_sign` calls
    `bitcointx.select_chain_params("bitcoin")`; address parsing rejects
    testnet/signet/regtest.

  - No certificate pinning for `frigate.2140.dev`.

  - The fee-rate estimator assumes a P2TR output (43 vB). For non-taproot
    destinations the script overpays slightly; it never underpays.

  - Python is not constant-time. `coincurve` / `libsecp256k1` avoid
    leakage in the primitives, but the surrounding Python is not hardened
    against an attacker with code-execution on the same host. Don't run
    this on shared infrastructure.
