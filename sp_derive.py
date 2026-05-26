#!/usr/bin/env python3
"""
sp_derive — derive BIP-352 scan / spend keys from an Electrum-style seed.

This is the only script in the toolkit that handles a mnemonic. It does no
network I/O and does not import socket, ssl, or urllib.

Reads:  24-word mnemonic from stdin. Echoed by default so long seeds can be
        verified word by word; pass --no-echo to read via getpass instead.
Writes: JSON with the derived keys, either to stdout (default; meant for
        piping to sp_scan) or to the path given by -o / --output, which is
        created with mode 0600. Status / warnings go to stderr.

Pipe to sp_scan to continue, or save and reuse:

    sp_derive.py --sp-address sp1... | sp_scan.py | sp_sign.py bc1p...
    sp_derive.py --sp-address sp1... -o keys.json

Usage:
    sp_derive.py --sp-address sp1... [-o keys.json]
"""
import argparse
import getpass
import json
import os
import signal
import sys

from coincurve import PrivateKey

import sp_crypto
import sp_ui

# Treat a closed downstream pipe like a regular Unix tool: exit, don't trace.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)


EPILOG = """\
example:
  sp_derive.py --sp-address sp1qq... -o keys.json
  sp_derive.py --sp-address sp1qq... | sp_scan.py | sp_sign.py bc1p...

This script is the ONLY one in the toolkit that handles a mnemonic.
It does no network I/O.
"""


def open_secret_file(path: str):
    """Open `path` write-only, truncating, mode 0600. The mode arg to
    os.open only applies on creation, so we also fchmod — otherwise an
    existing file with loose perms would still receive the spend_priv."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
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
        prog="sp_derive",
        description="Derive BIP-352 scan/spend keys from an Electrum-style seed.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--sp-address", required=True,
        help="your sp1... silent payment address; sanity gate before printing keys",
    )
    ap.add_argument(
        "--no-echo", action="store_true",
        help="read the mnemonic without echoing to the terminal (getpass)",
    )
    ap.add_argument(
        "-o", "--output",
        help="write JSON to this file (mode 0600) instead of stdout; "
             "use this OR pipe to sp_scan, not both",
    )
    ap.add_argument("--version", action="version", version=f"sp_derive {sp_crypto.__version__}")
    args = ap.parse_args()

    sp_address = args.sp_address.strip()
    if not sp_crypto.looks_like_sp_address(sp_address):
        sys.exit(
            "invalid --sp-address: expected an sp1... bech32m string, ~90-125 chars"
        )

    if args.no_echo:
        mnemonic = getpass.getpass("Enter your 24-word Electrum-style seed: ").strip()
    else:
        print("Enter your 24-word Electrum-style seed: ", end="", flush=True, file=sys.stderr)
        mnemonic = sys.stdin.readline().strip()
    if not mnemonic:
        sys.exit("no mnemonic provided")

    seed = sp_crypto.electrum_seed(mnemonic)
    keys = sp_crypto.find_derivation_path(seed, sp_address)
    if keys is None:
        sys.exit(
            "ABORT: this seed does not derive --sp-address at any candidate path.\n"
            "Either the seed is wrong, the address is wrong, or your wallet uses\n"
            "a path this script does not try. Refusing to print keys."
        )

    spend_pub = PrivateKey(keys.spend_priv).public_key.format(compressed=True)

    sp_ui.section("derived")
    sp_ui.kv([
        ("sp_address", sp_address),
        ("scan path", keys.scan_path),
        ("spend path", keys.spend_path),
        ("scan_key", keys.scan_key.hex()),
        ("spend_pub", spend_pub.hex()),
    ])
    where = f"file {args.output} (mode 0600)" if args.output else "stdout"
    print(
        f"\nWARNING: spend_priv is in the JSON on {where}. Anyone who reads it "
        "can spend your SP outputs. Clear shell history and scrollback when done.",
        file=sys.stderr,
    )

    payload = {
        "sp_address": sp_address,
        "scan_key": keys.scan_key.hex(),
        "spend_priv": keys.spend_priv.hex(),
        "spend_pub": spend_pub.hex(),
        "paths": {"scan": keys.scan_path, "spend": keys.spend_path},
    }
    if args.output:
        with open_secret_file(args.output) as f:
            json.dump(payload, f)
            f.write("\n")
    else:
        json.dump(payload, sys.stdout)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
