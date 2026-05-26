"""Pure-crypto utilities for BIP-352 silent payments.

No I/O. No network. No filesystem. No global state. Every function is pure
given its inputs. This is the file to audit if you want to convince yourself
the math is right; it is imported by sp_derive, sp_scan, and sp_sign.

Covers:
  - Electrum-style mnemonic -> 64-byte seed
  - BIP-32 derivation
  - BIP-352 shared-secret -> per-output tweak and signing key
  - bech32m + silent payment address encoding
  - find_derivation_path: walks Cake Wallet's candidate paths and returns
    the (scan, spend) pair that encodes to the user's SP address
"""
import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

from coincurve import PrivateKey, PublicKey

__version__ = "1.0.0"

CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000

# Candidate BIP-352 derivation paths observed in Cake Wallet builds. The
# find_derivation_path() helper tries each in order; if none encode to the
# user's --sp-address the toolkit aborts. Extend this list if you find a
# new path in the wild.
CANDIDATE_PATHS = [
    ("m/352'/1'/0",       "m/352'/1'/1"),
    ("m/352'/1'/0'",      "m/352'/1'/1'"),
    ("m/352'/1'/0'/0/0",  "m/352'/1'/0'/1/0"),
    ("m/352'/1'/0'/0'/0", "m/352'/1'/0'/1'/0"),
    ("m/352'/0'/0'/0'/0", "m/352'/0'/0'/1'/0"),
]


# ------------------ Electrum mnemonic -> 64-byte seed ------------------

def electrum_normalize(mnemonic: str) -> str:
    s = unicodedata.normalize("NFKD", mnemonic).lower()
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.split())


def electrum_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512",
        electrum_normalize(mnemonic).encode(),
        ("electrum" + passphrase).encode(),
        2048,
        dklen=64,
    )


# ------------------ BIP-32 ------------------

def bip32_master(seed: bytes):
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]


def bip32_ckd(parent_priv: bytes, parent_chain: bytes, index: int):
    if index >= HARDENED:
        data = b"\x00" + parent_priv + index.to_bytes(4, "big")
    else:
        parent_pub = PrivateKey(parent_priv).public_key.format(compressed=True)
        data = parent_pub + index.to_bytes(4, "big")
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    il_int = int.from_bytes(h[:32], "big")
    if il_int >= CURVE_N:
        raise ValueError("invalid child")
    child_int = (il_int + int.from_bytes(parent_priv, "big")) % CURVE_N
    if child_int == 0:
        raise ValueError("zero child")
    return child_int.to_bytes(32, "big"), h[32:]


def parse_path(path: str):
    out = []
    rest = path.removeprefix("m").removeprefix("/")
    for piece in rest.split("/"):
        if not piece:
            continue
        hardened = piece.endswith("'") or piece.endswith("h")
        out.append((int(piece.rstrip("'h")), hardened))
    return out


def derive_path(seed: bytes, path: str) -> bytes:
    priv, chain = bip32_master(seed)
    for idx, hardened in parse_path(path):
        priv, chain = bip32_ckd(priv, chain, idx + HARDENED if hardened else idx)
    return priv


# ------------------ BIP-352 ------------------

def tagged_hash(tag: str, msg: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + msg).digest()


def priv_key_tweak(b_scan: bytes, tweak_pubkey: bytes, k: int = 0) -> int:
    """BIP-352 additive tweak  t_k = H_BIP0352/SharedSecret(b_scan * T || k).

    Adding this to b_spend mod n yields the per-output signing private key.
    Knowing t_k alone is not enough to spend; you also need b_spend.
    """
    shared = PublicKey(tweak_pubkey).multiply(b_scan).format(compressed=True)
    return int.from_bytes(
        tagged_hash("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")),
        "big",
    ) % CURVE_N


def derive_signing_key(b_scan: bytes, b_spend_int: int, tweak_pubkey: bytes, k: int = 0) -> int:
    return (b_spend_int + priv_key_tweak(b_scan, tweak_pubkey, k)) % CURVE_N


def output_x_only_pubkey(signing_priv_int: int) -> bytes:
    """Return the 32-byte x-only pubkey for a BIP-352 signing private key.

    The on-chain SP output is OP_1 OP_PUSHBYTES_32 <this>.
    """
    return (
        PrivateKey(signing_priv_int.to_bytes(32, "big"))
        .public_key.format(compressed=True)[1:]
    )


# ------------------ Bech32m + SP address ------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32m_checksum(hrp, data):
    polymod = _bech32_polymod(_hrp_expand(hrp) + data + [0] * 6) ^ _BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for v in data:
        acc = ((acc << frombits) | v) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def encode_sp_address(scan_pub: bytes, spend_pub: bytes, hrp: str = "sp", version: int = 0) -> str:
    data = [version] + convertbits(scan_pub + spend_pub, 8, 5)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + _bech32m_checksum(hrp, data))


def looks_like_sp_address(s: str) -> bool:
    """Cheap shape check: hrp=sp, plausible length, only bech32 chars.
    Real validation happens when find_derivation_path tries to match it;
    this exists so callers can fail fast on obvious typos before doing
    sensitive work."""
    if not s.startswith("sp1"):
        return False
    if not (90 <= len(s) <= 125):
        return False
    return all(c in _BECH32_CHARSET for c in s[3:])


# ------------------ Seed -> keys (the load-bearing one for sp_derive) ------------------

@dataclass
class DerivedKeys:
    scan_key: bytes
    spend_priv: bytes
    scan_path: str
    spend_path: str


def find_derivation_path(seed: bytes, expected_sp_address: str):
    """Walk CANDIDATE_PATHS and return the (scan, spend) pair that encodes to
    expected_sp_address, or None if nothing matches."""
    for spend_path, scan_path in CANDIDATE_PATHS:
        try:
            spend_priv = derive_path(seed, spend_path)
            scan_key = derive_path(seed, scan_path)
            B_spend = PrivateKey(spend_priv).public_key.format(compressed=True)
            B_scan = PrivateKey(scan_key).public_key.format(compressed=True)
        except Exception:
            continue
        if encode_sp_address(B_scan, B_spend) == expected_sp_address:
            return DerivedKeys(
                scan_key=scan_key,
                spend_priv=spend_priv,
                scan_path=scan_path,
                spend_path=spend_path,
            )
    return None
