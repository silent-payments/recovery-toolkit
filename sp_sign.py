#!/usr/bin/env python3
"""
sp_sign — build and BIP-340-sign a sweep transaction from a UTXO set.

WHAT GOES OVER THE NETWORK
  Nothing. sp_sign does no network I/O. It does not import socket, ssl, or
  urllib. The signed transaction goes to stdout for you to broadcast.

Inputs:
  - --spend-priv hex (or from stdin JSON / --utxos file)
  - --utxos PATH  or  JSON on stdin   (the file/object emitted by sp_scan)
  - --feerate sat/vB  (or pulled from the utxos JSON if it has
    "suggested_feerate_sat_vb"; otherwise required)
  - positional destination address

Output:
  signed transaction hex on stdout (one line)
  summary + confirmation prompt on stderr / /dev/tty

Before signing, sp_sign recomputes  D = (spend_priv + priv_key_tweak)*G
for each UTXO and aborts if it doesn't match the stored scriptPubKey.
That catches typos / wrong key / wrong utxos.json without revealing
anything sensitive.

Usage:
    sp_scan.py < derived.json | sp_sign.py bc1p...
    sp_sign.py --utxos scanned.json --spend-priv 9d... --feerate 15 bc1p...
"""
import argparse
import json
import signal
import sys
from dataclasses import dataclass

from coincurve import PrivateKey, PublicKeyXOnly

from bitcointx import select_chain_params
from bitcointx.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxInWitness,
    CMutableTxOut,
    COutPoint,
    CTxOut,
)
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    SignatureHashSchnorr,
)
from bitcointx.wallet import CCoinAddress

import sp_crypto
import sp_ui

select_chain_params("bitcoin")
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

DUST_LIMIT_SAT = 330


@dataclass
class Utxo:
    txid: str
    vout: int
    value_sat: int
    script_pub_key: bytes
    priv_key_tweak: int

    def __post_init__(self):
        # Validate shape up front so the signing loop can trust the bytes.
        if len(bytes.fromhex(self.txid)) != 32:
            raise ValueError(f"txid must be 32 bytes hex, got {self.txid!r}")
        if self.vout < 0:
            raise ValueError(f"vout must be non-negative, got {self.vout}")
        if self.value_sat <= 0:
            raise ValueError(f"value_sat must be positive, got {self.value_sat}")
        if len(self.script_pub_key) != 34 or self.script_pub_key[:2] != b"\x51\x20":
            raise ValueError(
                f"scriptPubKey must be 34 bytes starting with 5120, "
                f"got {self.script_pub_key.hex()!r}"
            )
        if not (0 < self.priv_key_tweak < sp_crypto.CURVE_N):
            raise ValueError("priv_key_tweak must be in [1, n-1]")

    @classmethod
    def from_dict(cls, d: dict) -> "Utxo":
        try:
            return cls(
                txid=d["txid"],
                vout=int(d["vout"]),
                value_sat=int(d["value_sat"]),
                script_pub_key=bytes.fromhex(d["scriptPubKey"]),
                priv_key_tweak=int(d["priv_key_tweak"], 16),
            )
        except (KeyError, ValueError) as e:
            raise ValueError(f"malformed utxo entry: {e}") from e


def estimate_vsize(n_taproot_inputs: int, n_taproot_outputs: int) -> int:
    # P2TR key-path: 41 B prevout + ~16.5 vB witness per input, 43 B per
    # output, 10.5 vB tx overhead.
    return int(round(
        10.5 + 41 * n_taproot_inputs + 16.5 * n_taproot_inputs + 43 * n_taproot_outputs
    ))


def verify_utxo_key(utxo: Utxo, spend_priv_int: int) -> int:
    """Check spend_priv matches this UTXO's scriptPubKey via BIP-352, and
    return the per-output signing key d.  Raises ValueError on mismatch."""
    d_int = (spend_priv_int + utxo.priv_key_tweak) % sp_crypto.CURVE_N
    if not (0 < d_int < sp_crypto.CURVE_N):
        raise ValueError(f"{utxo.txid}:{utxo.vout}  signing key out of range")
    D_xonly = sp_crypto.output_x_only_pubkey(d_int)
    expected = b"\x51\x20" + D_xonly
    if expected != utxo.script_pub_key:
        raise ValueError(
            f"{utxo.txid}:{utxo.vout}  spend_priv does not match scriptPubKey; "
            "wrong spend_priv or wrong utxos file"
        )
    return d_int


def build_and_sign(utxos: list, destination: str, fee_sat: int, spend_priv_int: int) -> str:
    """Build a P2TR sweep tx and BIP-340-sign every input.  BIP-352 outputs
    commit D = d*G directly as the x-only output key (no BIP-341 H_TapTweak),
    so we schnorr-sign with d as-is."""
    total_in = sum(u.value_sat for u in utxos)
    out_sat = total_in - fee_sat
    if out_sat < DUST_LIMIT_SAT:
        raise ValueError(f"sweep amount below dust ({out_sat} sat)")

    dest_spk = bytes(CCoinAddress(destination).to_scriptPubKey())

    vins = [
        CMutableTxIn(
            COutPoint(bytes.fromhex(u.txid)[::-1], u.vout),
            nSequence=0xFFFFFFFD,
        )
        for u in utxos
    ]
    vouts = [CMutableTxOut(out_sat, CScript(dest_spk))]
    tx = CMutableTransaction(vin=vins, vout=vouts, nLockTime=0)

    spent_outputs = [
        CTxOut(u.value_sat, CScript(u.script_pub_key)) for u in utxos
    ]

    for i, u in enumerate(utxos):
        d_int = verify_utxo_key(u, spend_priv_int)
        sighash = SignatureHashSchnorr(tx, i, spent_outputs)
        sig = PrivateKey(d_int.to_bytes(32, "big")).sign_schnorr(sighash)
        if len(sig) != 64:
            raise RuntimeError(f"unexpected schnorr sig length: {len(sig)}")
        # Defense in depth: verify our own signature before placing it.
        if not PublicKeyXOnly(u.script_pub_key[2:]).verify(sig, sighash):
            raise RuntimeError(f"self-verify failed for input {i}")
        tx.wit.vtxinwit[i] = CMutableTxInWitness(CScriptWitness([sig]))

    return tx.serialize().hex()


def load_pipe_input() -> dict:
    if sys.stdin.isatty():
        return {}
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"stdin JSON parse error: {e}")
    if not isinstance(data, dict):
        sys.exit("stdin JSON must be an object")
    return data


def confirm_via_tty(question: str) -> bool:
    """Prompt on /dev/tty (not stdin) so it works even when stdin was a pipe."""
    try:
        with open("/dev/tty", "r+", buffering=1) as tty:
            tty.write(question)
            tty.flush()
            answer = tty.readline().strip().lower()
            return answer == "yes"
    except OSError:
        return False


EPILOG = """\
examples:
  # pipe mode:
  sp_derive.py --sp-address sp1qq... | sp_scan.py | sp_sign.py bc1p...

  # standalone:
  sp_sign.py --utxos scanned.json --spend-priv 9d6a... --feerate 8 bc1p...

  # non-interactive (skip confirmation prompt):
  sp_sign.py --utxos scanned.json --spend-priv 9d6a... --feerate 8 --yes bc1p...
"""


def main():
    try:
        _main()
    except KeyboardInterrupt:
        sys.stderr.write("\naborted\n")
        sys.exit(130)


def _main():
    ap = argparse.ArgumentParser(
        prog="sp_sign",
        description="BIP-340-sign a sweep transaction. Does NOT broadcast.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("destination", help="bech32m P2TR address to sweep to")
    ap.add_argument("--spend-priv", help="32-byte spend privkey hex (or from stdin/--utxos JSON)")
    ap.add_argument("--utxos", help="path to a sp_scan JSON file; omit to read from stdin")
    ap.add_argument(
        "--feerate", type=float, default=None,
        help="sat/vB; required unless utxos JSON has suggested_feerate_sat_vb",
    )
    ap.add_argument(
        "--yes", action="store_true",
        help="skip the confirmation prompt (use with care)",
    )
    ap.add_argument("--version", action="version", version=f"sp_sign {sp_crypto.__version__}")
    args = ap.parse_args()

    # Fail fast on a malformed destination before touching any key material
    # or prompting for confirmation.
    try:
        dest_spk = bytes(CCoinAddress(args.destination).to_scriptPubKey())
    except Exception as e:
        sys.exit(f"invalid destination address: {e}")

    if args.utxos:
        with open(args.utxos) as f:
            pipe = json.load(f)
    else:
        pipe = load_pipe_input()
    if not isinstance(pipe, dict):
        sys.exit("utxos JSON must be an object (the output of sp_scan)")

    spend_priv_hex = args.spend_priv or pipe.get("spend_priv")
    if not spend_priv_hex:
        sys.exit("missing spend_priv (pass via --spend-priv or pipe in JSON)")
    try:
        spend_priv_bytes = bytes.fromhex(spend_priv_hex)
    except ValueError:
        sys.exit("spend_priv: not valid hex")
    if len(spend_priv_bytes) != 32:
        sys.exit(f"spend_priv: expected 32 bytes, got {len(spend_priv_bytes)}")
    spend_priv_int = int.from_bytes(spend_priv_bytes, "big")
    if not (0 < spend_priv_int < sp_crypto.CURVE_N):
        sys.exit("invalid spend_priv (not in [1, n-1])")

    raw_utxos = pipe.get("utxos") or []
    if not raw_utxos:
        sys.exit("no utxos to sign")
    try:
        utxos = [Utxo.from_dict(u) for u in raw_utxos]
    except ValueError as e:
        sys.exit(f"ABORT: {e}")

    feerate = args.feerate
    if feerate is None:
        feerate = pipe.get("suggested_feerate_sat_vb")
    if feerate is None:
        sys.exit("no fee rate available; pass --feerate <sat/vB>")
    feerate = float(feerate)

    # Pre-flight: verify every utxo against spend_priv before showing a
    # summary, so we don't tease the user with a sweep they can't sign.
    try:
        for u in utxos:
            verify_utxo_key(u, spend_priv_int)
    except ValueError as e:
        sys.exit(f"ABORT: {e}")

    total_in = sum(u.value_sat for u in utxos)
    vsize = estimate_vsize(len(utxos), 1)
    fee_sat = int(round(vsize * feerate))
    out_sat = total_in - fee_sat
    if out_sat < DUST_LIMIT_SAT:
        sys.exit(f"sweep amount below dust (in: {total_in} sat, fee: {fee_sat} sat)")

    sp_ui.section("sweep")
    sp_ui.kv([
        ("inputs", len(utxos)),
        ("total in", f"{total_in:>14,} sat  ({total_in/1e8:.8f} BTC)"),
        ("fee est.", f"{fee_sat:>14,} sat  @ {feerate:.2f} sat/vB on {vsize} vB"),
        ("total out", f"{out_sat:>14,} sat  ({out_sat/1e8:.8f} BTC)"),
        ("to", args.destination),
        ("spk", dest_spk.hex()),
    ])
    sys.stderr.write("\n")

    if not args.yes and not confirm_via_tty("Type 'yes' to sign: "):
        sys.exit("aborted")

    signed_hex = build_and_sign(utxos, args.destination, fee_sat, spend_priv_int)

    # Flush stderr before writing the hex so terminal output stays in order
    # (summary, then hex, then broadcast hint) regardless of buffering.
    sys.stderr.write("\nsigned transaction:\n")
    sys.stderr.flush()
    sys.stdout.write(signed_hex + "\n")
    sys.stdout.flush()
    sys.stderr.write(
        "\nTo broadcast: paste the hex into https://mempool.space/tx/push\n"
        "(or any wallet/tool that accepts a raw signed transaction).\n"
    )
    sys.stderr.flush()


if __name__ == "__main__":
    main()
