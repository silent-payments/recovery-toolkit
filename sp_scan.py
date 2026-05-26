#!/usr/bin/env python3
"""
sp_scan — fetch BIP-352 silent-payment history for a (scan_key, spend_pub).

WHAT GOES OVER THE NETWORK
  Outbound to --server only (default frigate.2140.dev:50002, TLS):
    - scan_key hex + spend_pub hex (per the Frigate silentpayments scan RPC)
    - scripthash listunspent / transaction.get queries
    - blockchain.estimatefee
  Never sent: spend_priv, the destination address, anything from sp_sign.

Inputs:
  - --scan-key and --spend-pub on the CLI, OR a JSON object on stdin
    (e.g. from sp_derive) carrying {"scan_key": "...", "spend_pub": "..."}.
  - spend_priv is never accepted on the CLI. When piped in from sp_derive
    it is propagated untouched on stdout so sp_sign can read it; spend_priv
    is never used by sp_scan itself.

Output (JSON on stdout):
  {
    "spend_priv":   <hex>,                    # only if it was piped in
    "sp_address":   <sp1...>,                 # passthrough if provided
    "history":      [ {height, txid, vout,    # full tx history at the SP
                       value_sat, scriptPubKey,
                       priv_key_tweak, spent} ],
    "utxos":        [ {txid, vout, value_sat, # the unspent subset, in the
                       scriptPubKey,          # shape sp_sign expects
                       priv_key_tweak} ],
    "suggested_feerate_sat_vb": <float or null>,
    "server":       "host:port",
    "scanned_from_height": <int>              # --start (default: taproot
                                              # activation, block 709632)
  }

Usage:
  sp_derive.py --sp-address sp1... | sp_scan.py | sp_sign.py bc1p...
  sp_scan.py --scan-key 0f... --spend-pub 03... -o scanned.json
"""
import argparse
import hashlib
import json
import os
import signal
import socket
import ssl
import sys
from typing import Callable, Optional

from coincurve import PrivateKey, PublicKey

import sp_crypto
import sp_ui

# Treat a closed downstream pipe like a regular Unix tool: exit, don't trace.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

DEFAULT_FRIGATE = "frigate.2140.dev:50002"

# BIP-352 outputs are P2TR, so nothing relevant exists before taproot activated.
TAPROOT_ACTIVATION_HEIGHT = 709632


# ------------------ Frigate Electrum client ------------------

class FrigateClient:
    """Electrum JSON-RPC over a single long-lived TLS connection.

    Frigate implements blockchain.silentpayments.subscribe natively and
    proxies all other Electrum methods to a backend full-node-indexer, so
    this one client covers the entire flow.

    Use as a context manager.  Methods raise RuntimeError on protocol
    errors (closed connection, error response, etc.).
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock = None
        self._reader = None
        self._req_id = 0

    def __enter__(self):
        ctx = ssl.create_default_context()
        raw = socket.create_connection((self.host, self.port), timeout=30)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self._sock.settimeout(300)
        self._reader = self._sock.makefile("rb")
        # Frigate requires server.version as the first message on every connection.
        self.call("server.version", [f"sp_scan {sp_crypto.__version__}", "1.4"])
        return self

    def __exit__(self, *exc):
        try:
            if self._sock is not None:
                self._sock.close()
        finally:
            self._sock = None
            self._reader = None

    def _send(self, method: str, params: list) -> int:
        self._req_id += 1
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }) + "\n"
        self._sock.sendall(req.encode())
        return self._req_id

    def _readline(self) -> dict:
        line = self._reader.readline()
        if not line:
            raise RuntimeError("frigate closed the connection")
        return json.loads(line)

    def call(self, method: str, params: list):
        req_id = self._send(method, params)
        while True:
            msg = self._readline()
            if msg.get("id") != req_id:
                continue
            if msg.get("error"):
                raise RuntimeError(f"{method}: {msg['error']}")
            return msg.get("result")

    def scan(
        self,
        scan_key: bytes,
        spend_pub: bytes,
        start: int = TAPROOT_ACTIVATION_HEIGHT,
        on_subscribed: Optional[Callable[[dict], None]] = None,
        on_progress: Optional[Callable[[float, int], None]] = None,
    ):
        """blockchain.silentpayments.subscribe -> accumulated history once
        progress == 1.0.  Callbacks fire as events come in; both default
        to no-op so this method is silent."""
        req_id = self._send(
            "blockchain.silentpayments.subscribe",
            [scan_key.hex(), spend_pub.hex(), start],
        )
        while True:
            msg = self._readline()
            if msg.get("id") != req_id:
                continue
            if msg.get("error"):
                raise RuntimeError(f"subscribe: {msg['error']}")
            if on_subscribed:
                on_subscribed(msg.get("result") or {})
            break

        history = []
        while True:
            msg = self._readline()
            if msg.get("method") != "blockchain.silentpayments.subscribe":
                continue
            # Frigate sends params as a named object {subscription, progress,
            # history}, not the positional array shape used by most Electrum
            # notifications. Accept either so we work against both flavors.
            params = msg.get("params")
            if isinstance(params, dict):
                progress = params.get("progress")
                chunk = params.get("history") or []
            elif isinstance(params, list) and len(params) >= 3:
                progress, chunk = params[1], params[2] or []
            else:
                continue
            if progress is None:
                continue
            if chunk:
                history.extend(chunk)
            if on_progress:
                on_progress(float(progress), len(history))
            if float(progress) >= 1.0:
                return history


# ------------------ Electrum helpers ------------------

def scripthash(spk: bytes) -> str:
    """Electrum scripthash: sha256(scriptPubKey), bytes reversed, hex."""
    return hashlib.sha256(spk).digest()[::-1].hex()


def find_unspent_match(client: FrigateClient, txid: str, spk: bytes):
    """listunspent at sha256(spk).rev, filter to our txid.  Returns
    (vout, value_sat) if the output is still unspent, else None."""
    unspent = client.call("blockchain.scripthash.listunspent", [scripthash(spk)]) or []
    match = next((u for u in unspent if u.get("tx_hash") == txid), None)
    if match is None:
        return None
    return int(match["tx_pos"]), int(match["value"])


def find_spent_match(client: FrigateClient, txid: str, spk_hex: str):
    """Look up the receiving tx and find which vout has our scriptPubKey.
    Used when listunspent came up empty (output likely spent).  Returns
    (vout, value_sat) or None if no vout matches (false positive)."""
    tx = client.call("blockchain.transaction.get", [txid, True])
    if not isinstance(tx, dict):
        return None
    for vout_idx, vout in enumerate(tx.get("vout", [])):
        if (vout.get("scriptPubKey") or {}).get("hex") == spk_hex:
            value_sat = int(round(float(vout["value"]) * 1e8))
            return vout_idx, value_sat
    return None


def fetch_feerate(client: FrigateClient, target_blocks: int = 6):
    """blockchain.estimatefee -> sat/vB, or None if estimate is unavailable.
    A None return is propagated so the user (or sp_sign) is forced to make
    an explicit choice rather than getting silently underpriced."""
    btc_per_kvb = client.call("blockchain.estimatefee", [target_blocks])
    if not isinstance(btc_per_kvb, (int, float)) or btc_per_kvb <= 0:
        return None
    return float(btc_per_kvb) * 1e8 / 1000


# ------------------ scan orchestration ------------------

def load_pipe_input() -> dict:
    """Pull a JSON object from stdin if it isn't a terminal, else return {}."""
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


def resolve_required(name: str, cli_value, pipe_value):
    val = cli_value or pipe_value
    if not val:
        sys.exit(f"missing {name} (pass via --{name.replace('_', '-')} or pipe in JSON)")
    return val


def _parse_hex(label: str, hex_str: str, expected_len: int) -> bytes:
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        sys.exit(f"{label}: not valid hex")
    if len(b) != expected_len:
        sys.exit(f"{label}: expected {expected_len} bytes, got {len(b)}")
    return b


def run_scan(args, pipe: dict) -> dict:
    scan_key = _parse_hex(
        "scan_key",
        resolve_required("scan_key", args.scan_key, pipe.get("scan_key")),
        32,
    )
    spend_pub = _parse_hex(
        "spend_pub",
        resolve_required("spend_pub", args.spend_pub, pipe.get("spend_pub")),
        33,
    )

    scan_key_int = int.from_bytes(scan_key, "big")
    if not (0 < scan_key_int < sp_crypto.CURVE_N):
        sys.exit("invalid scan_key (not in [1, n-1])")
    try:
        scan_pub = PrivateKey(scan_key).public_key.format(compressed=True)
        PublicKey(spend_pub)
    except Exception as e:
        sys.exit(f"invalid key inputs: {e}")
    if pipe.get("sp_address"):
        if sp_crypto.encode_sp_address(scan_pub, spend_pub) != pipe["sp_address"]:
            sys.exit("sanity check failed: keys do not encode to pipe sp_address")

    host, _, port_s = args.server.partition(":")
    port = int(port_s) if port_s else 50002

    history: list = []
    utxos: list = []
    suggested_feerate: Optional[float] = None

    def log(msg):
        print(msg, file=sys.stderr)

    with FrigateClient(host, port) as client:
        log(f"connecting to frigate at {host}:{port} ...")
        entries = client.scan(
            scan_key, spend_pub, args.start,
            on_subscribed=lambda sub: log(
                f"subscribed: {sub.get('address', '?')} from height "
                f"{sub.get('start_height', '?')}"
            ),
            on_progress=lambda pct, n: log(
                f"  scan progress {pct*100:5.1f}%  ({n} candidates so far)"
            ),
        )

        log(f"\nresolving {len(entries)} candidates ...\n")
        n_entries = len(entries)
        for idx, entry in enumerate(entries):
            txid = entry["tx_hash"]
            tweak_hex = entry["tweak_key"]
            t_0 = sp_crypto.priv_key_tweak(scan_key, bytes.fromhex(tweak_hex), 0)
            # D = (B_spend) + t_0 * G, expressed at the pubkey layer so we
            # never combine spend_priv (we don't have it here).
            t_pub = PrivateKey(t_0.to_bytes(32, "big")).public_key
            D_pub = PublicKey.combine_keys([PublicKey(spend_pub), t_pub])
            D_xonly = D_pub.format(compressed=True)[1:]
            spk = b"\x51\x20" + D_xonly
            spk_hex = spk.hex()

            unspent = find_unspent_match(client, txid, spk)
            if unspent is not None:
                vout, value_sat = unspent
                spent = False
            else:
                spent_lookup = find_spent_match(client, txid, spk_hex)
                if spent_lookup is None:
                    continue
                vout, value_sat = spent_lookup
                spent = True

            record = {
                "height": entry.get("height", 0),
                "txid": txid,
                "vout": vout,
                "value_sat": value_sat,
                "scriptPubKey": spk_hex,
                "priv_key_tweak": t_0.to_bytes(32, "big").hex(),
                "spent": spent,
            }
            history.append(record)
            if not spent:
                utxos.append({k: record[k] for k in (
                    "txid", "vout", "value_sat", "scriptPubKey", "priv_key_tweak"
                )})

        suggested_feerate = fetch_feerate(client)

    if history:
        sp_ui.section("history")
        sp_ui.table(
            ["HEIGHT", "TXID", "VOUT", "VALUE_SAT", "STATUS"],
            [
                (
                    r["height"],
                    r["txid"],
                    r["vout"],
                    f"{r['value_sat']:,}",
                    "SPENT" if r["spent"] else "unspent",
                )
                for r in history
            ],
            align=["r", "l", "r", "r", "l"],
        )

    unspent_sat = sum(u["value_sat"] for u in utxos)
    spent_n = sum(1 for h in history if h["spent"])
    spent_sat = sum(h["value_sat"] for h in history if h["spent"])
    sp_ui.section("summary")
    summary_rows = [
        ("server", args.server),
        ("scanned from", f"height {args.start}"),
        ("candidates", len(history)),
        ("unspent", f"{len(utxos)} ({unspent_sat:,} sat)"),
        ("spent", f"{spent_n} ({spent_sat:,} sat)"),
        ("feerate", f"{suggested_feerate:.2f} sat/vB" if suggested_feerate is not None
                    else "unavailable (sp_sign will require --feerate)"),
    ]
    if args.output:
        summary_rows.append(("output", args.output))
    sp_ui.kv(summary_rows)

    out = {
        "server": args.server,
        "scanned_from_height": args.start,
        "history": history,
        "utxos": utxos,
        "suggested_feerate_sat_vb": suggested_feerate,
    }
    # Pipe-through fields (sp_sign will consume spend_priv).
    if pipe.get("spend_priv"):
        out["spend_priv"] = pipe["spend_priv"]
    if pipe.get("sp_address"):
        out["sp_address"] = pipe["sp_address"]
    return out


EPILOG = """\
examples:
  # pipe mode (reads keys from upstream sp_derive JSON):
  sp_derive.py --sp-address sp1qq... | sp_scan.py -o scanned.json

  # standalone (watch-only, no spend_priv ever enters this process):
  sp_scan.py --scan-key 0f694e... --spend-pub 03e331... -o scanned.json

  # against your own Frigate instance:
  sp_scan.py --server frigate.local:50002 --scan-key ... --spend-pub ...
"""


def open_output_file(path: str, secret: bool):
    """Open `path` write-only, truncating. When `secret` is true (i.e.
    spend_priv was piped through from sp_derive), force mode 0600 — both
    on the create path via os.open's mode arg and via fchmod, so an
    existing file with loose perms is also tightened before we write."""
    mode = 0o600 if secret else 0o644
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    if secret:
        os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w")


def main():
    try:
        _main()
    except KeyboardInterrupt:
        sys.stderr.write("\naborted\n")
        sys.exit(130)


def _main():
    ap = argparse.ArgumentParser(
        prog="sp_scan",
        description="Scan a Frigate Electrum server for BIP-352 SP outputs.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--scan-key", help="32-byte BIP-352 scan key hex (or from stdin JSON)")
    ap.add_argument("--spend-pub", help="33-byte compressed spend pubkey hex (or from stdin JSON)")
    ap.add_argument(
        "--server", default=DEFAULT_FRIGATE,
        help=f"Frigate Electrum host:port (default {DEFAULT_FRIGATE})",
    )
    ap.add_argument(
        "--start", type=int, default=TAPROOT_ACTIVATION_HEIGHT,
        help=f"scan from this block height (default {TAPROOT_ACTIVATION_HEIGHT}, taproot activation)",
    )
    ap.add_argument(
        "-o", "--output",
        help="write JSON to this file instead of stdout; "
             "use this OR pipe to sp_sign, not both",
    )
    ap.add_argument("--version", action="version", version=f"sp_scan {sp_crypto.__version__}")
    args = ap.parse_args()

    pipe = load_pipe_input()
    result = run_scan(args, pipe)
    if args.output:
        with open_output_file(args.output, secret="spend_priv" in result) as f:
            json.dump(result, f, indent=2)
            f.write("\n")
    else:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
