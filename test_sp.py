"""Tests for sp_crypto, sp_derive, sp_scan, and sp_sign.

Run with: python3 -m unittest test_sp
"""
import hashlib
import json
import os
import stat
import tempfile
import unittest

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

import sp_crypto
import sp_derive
import sp_scan
import sp_sign


# ------------------ encode_sp_address ------------------
#
# Inputs taken from the previously-hardcoded EXPECTED_SP_ADDRESS by decoding it
# once (bech32m -> 5-bit -> 8-bit -> drop version byte -> split 33/33). These
# are the (B_scan, B_spend) compressed-secp256k1 pubkeys the SP address commits
# to. A round-trip mismatch would mean the bech32m/convertbits/encode path has
# regressed.
B_SCAN = bytes.fromhex(
    "03193836269c83b31ef39ab9d7e4b0fff71aacb22352702730463d3bb4c815a127"
)
B_SPEND = bytes.fromhex(
    "03e331a3e9a4504687c1e68c774aa4da0dd269dd0ecfa586ff2dd76d29c8f6e0e1"
)
EXPECTED_SP_ADDRESS = (
    "sp1qqvvnsd3xnjpmx8hnn2ua0e9sllm34t9jydf8qfesgc7nhdxgzksjwqlrxx37nfzsg6"
    "rure5vwa92fksd6f5a6rk05kr07twhd55u3ahquy2v7t6s"
)


class EncodeSpAddressTests(unittest.TestCase):
    def test_matches_previously_hardcoded_value(self):
        self.assertEqual(
            sp_crypto.encode_sp_address(B_SCAN, B_SPEND),
            EXPECTED_SP_ADDRESS,
        )

    def test_convertbits_roundtrip(self):
        bytes8 = list(range(66))
        bits5 = sp_crypto.convertbits(bytes8, 8, 5, pad=True)
        back = sp_crypto.convertbits(bits5, 5, 8, pad=False)
        self.assertEqual(back, bytes8)


# ------------------ tagged_hash / BIP-352 ------------------

class TaggedHashTests(unittest.TestCase):
    def test_matches_bip340_formula(self):
        tag = "BIP0352/SharedSecret"
        msg = b"hello world"
        expected = hashlib.sha256(
            hashlib.sha256(tag.encode()).digest() * 2 + msg
        ).digest()
        self.assertEqual(sp_crypto.tagged_hash(tag, msg), expected)


class DeriveSigningKeyTests(unittest.TestCase):
    def test_pubkey_consistency_scalar_vs_point(self):
        """d*G must equal B_spend + t*G — catches scalar/point arithmetic bugs."""
        b_scan = bytes.fromhex("01" + "00" * 30 + "02")
        b_spend_int = (
            0x4242424242424242424242424242424242424242424242424242424242424242
        )
        tweak_priv = bytes.fromhex("03" * 32)
        tweak_pub = PrivateKey(tweak_priv).public_key.format(compressed=True)

        d = sp_crypto.derive_signing_key(b_scan, b_spend_int, tweak_pub, k=0)

        shared = PublicKey(tweak_pub).multiply(b_scan).format(compressed=True)
        t_int = int.from_bytes(
            sp_crypto.tagged_hash("BIP0352/SharedSecret", shared + b"\x00" * 4),
            "big",
        ) % sp_crypto.CURVE_N

        D_from_scalar = PrivateKey(d.to_bytes(32, "big")).public_key
        B_spend = PrivateKey(b_spend_int.to_bytes(32, "big")).public_key
        t_pub = PrivateKey(t_int.to_bytes(32, "big")).public_key
        D_from_point = PublicKey.combine_keys([B_spend, t_pub])

        self.assertEqual(
            D_from_scalar.format(compressed=True),
            D_from_point.format(compressed=True),
        )

    def test_k_param_affects_output(self):
        b_scan = bytes.fromhex("01" * 32)
        b_spend_int = 0x01
        tweak_priv = bytes.fromhex("02" * 32)
        tweak_pub = PrivateKey(tweak_priv).public_key.format(compressed=True)
        d0 = sp_crypto.derive_signing_key(b_scan, b_spend_int, tweak_pub, k=0)
        d1 = sp_crypto.derive_signing_key(b_scan, b_spend_int, tweak_pub, k=1)
        self.assertNotEqual(d0, d1)


# BIP-352 test vectors (verbatim from
# https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
# — k=0, unlabeled, single output). Each entry exercises both priv_key_tweak()
# and derive_signing_key() against the BIP's stated outputs.
BIP352_VECTORS = [
    {
        "name": "Simple send: two inputs",
        "scan_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "spend_priv": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "tweak": "024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004",
        "priv_key_tweak": "f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6",
        "pub_key": "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
    },
    {
        "name": "Single recipient: multiple UTXOs from the same public key",
        "scan_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "spend_priv": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "tweak": "0319949463fc6a2368d999a2a6a2bcb2dbf64a2ac6e00b3ba5659780c860a6d9e0",
        "priv_key_tweak": "f032695e2636619efa523fffaa9ef93c8802299181fd0461913c1b8daf9784cd",
        "pub_key": "548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566",
    },
    {
        "name": "Single recipient: taproot only inputs with even y-values",
        "scan_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "spend_priv": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "tweak": "02dc59cc8e8873b65c1dd5c416d4fbeb647372c329bd84a70c05b310e222e2c183",
        "priv_key_tweak": "3fb9ce5ce1746ced103c8ed254e81f6690764637ddbc876ec1f9b3ddab776b03",
        "pub_key": "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb",
    },
]


class Bip352VectorTests(unittest.TestCase):
    def test_priv_key_tweak_matches_bip(self):
        for v in BIP352_VECTORS:
            with self.subTest(v["name"]):
                t = sp_crypto.priv_key_tweak(
                    bytes.fromhex(v["scan_key"]),
                    bytes.fromhex(v["tweak"]),
                    k=0,
                )
                self.assertEqual(t.to_bytes(32, "big").hex(), v["priv_key_tweak"])

    def test_derive_signing_key_matches_pub_key(self):
        for v in BIP352_VECTORS:
            with self.subTest(v["name"]):
                d = sp_crypto.derive_signing_key(
                    bytes.fromhex(v["scan_key"]),
                    int(v["spend_priv"], 16),
                    bytes.fromhex(v["tweak"]),
                    k=0,
                )
                self.assertEqual(
                    sp_crypto.output_x_only_pubkey(d).hex(),
                    v["pub_key"],
                )


# ------------------ BIP-32 ------------------

BIP32_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class Bip32Tests(unittest.TestCase):
    def test_master(self):
        priv, chain = sp_crypto.bip32_master(BIP32_SEED)
        self.assertEqual(
            priv.hex(),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        self.assertEqual(
            chain.hex(),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        )

    def test_derive_m_0h(self):
        self.assertEqual(
            sp_crypto.derive_path(BIP32_SEED, "m/0'").hex(),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        )

    def test_derive_m_0h_1(self):
        self.assertEqual(
            sp_crypto.derive_path(BIP32_SEED, "m/0'/1").hex(),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        )

    def test_derive_m_0h_1_2h(self):
        self.assertEqual(
            sp_crypto.derive_path(BIP32_SEED, "m/0'/1/2'").hex(),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        )

    def test_parse_path_apostrophe_and_h(self):
        self.assertEqual(
            sp_crypto.parse_path("m/0'/1h/2"),
            [(0, True), (1, True), (2, False)],
        )

    def test_parse_path_empty_root(self):
        self.assertEqual(sp_crypto.parse_path("m"), [])
        self.assertEqual(sp_crypto.parse_path("m/"), [])


# ------------------ Electrum mnemonic ------------------

class ElectrumMnemonicTests(unittest.TestCase):
    def test_normalize_lowercases_and_collapses_whitespace(self):
        self.assertEqual(
            sp_crypto.electrum_normalize("  Foo   BaR\tBaz\n"),
            "foo bar baz",
        )

    def test_normalize_strips_combining_marks(self):
        # NFKD decomposes 'É' to 'E' + U+0301, lowercased to 'e' + combining
        # acute; the combining mark is then stripped.
        self.assertEqual(sp_crypto.electrum_normalize("É"), "e")

    def test_seed_is_pbkdf2_sha512(self):
        mnemonic = "abandon abandon abandon"
        expected = hashlib.pbkdf2_hmac(
            "sha512",
            mnemonic.encode(),
            b"electrum",
            2048,
            dklen=64,
        )
        self.assertEqual(sp_crypto.electrum_seed(mnemonic), expected)


# ------------------ scripthash / vsize ------------------

class ScripthashTests(unittest.TestCase):
    def test_known_vector(self):
        spk = bytes.fromhex("5120" + "ab" * 32)
        expected = hashlib.sha256(spk).digest()[::-1].hex()
        self.assertEqual(sp_scan.scripthash(spk), expected)


class EstimateVsizeTests(unittest.TestCase):
    def test_one_in_one_out(self):
        self.assertEqual(sp_sign.estimate_vsize(1, 1), 111)

    def test_three_in_one_out(self):
        self.assertEqual(sp_sign.estimate_vsize(3, 1), 226)


# ------------------ FrigateClient (fake socket) ------------------

class _FakeSock:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        pass


class _FakeReader:
    def __init__(self, lines):
        normalized = []
        for line in lines:
            if isinstance(line, str):
                line = line.encode()
            if not line.endswith(b"\n"):
                line = line + b"\n"
            normalized.append(line)
        self._lines = iter(normalized)

    def readline(self):
        return next(self._lines, b"")


def _make_client(lines):
    client = sp_scan.FrigateClient("test.invalid", 1)
    client._sock = _FakeSock()
    client._reader = _FakeReader(lines)
    return client


class FrigateClientCallTests(unittest.TestCase):
    def test_returns_matching_result_and_sends_request(self):
        client = _make_client(['{"jsonrpc":"2.0","id":1,"result":["a","b"]}'])
        self.assertEqual(client.call("foo", [1, 2]), ["a", "b"])
        msg = json.loads(client._sock.sent[0].decode().strip())
        self.assertEqual(msg["method"], "foo")
        self.assertEqual(msg["params"], [1, 2])
        self.assertEqual(msg["id"], 1)

    def test_skips_interleaved_notifications(self):
        client = _make_client([
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":1.0,"history":[]}}',
            '{"jsonrpc":"2.0","id":1,"result":42}',
        ])
        self.assertEqual(client.call("foo", []), 42)

    def test_raises_on_error_response(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"bad"}}',
        ])
        with self.assertRaises(RuntimeError):
            client.call("foo", [])

    def test_raises_on_eof_before_response(self):
        client = _make_client([])
        with self.assertRaises(RuntimeError):
            client.call("foo", [])

    def test_request_ids_increment(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":1}',
            '{"jsonrpc":"2.0","id":2,"result":2}',
        ])
        client.call("a", [])
        client.call("b", [])
        ids = [json.loads(p.decode().strip())["id"] for p in client._sock.sent]
        self.assertEqual(ids, [1, 2])


class FrigateClientScanTests(unittest.TestCase):
    def _keys(self):
        scan_key = b"\x01" * 32
        spend_pub = PrivateKey(b"\x02" * 32).public_key.format(compressed=True)
        return scan_key, spend_pub

    def test_accumulates_history_across_chunks(self):
        # Frigate's real wire format: params is a named object, not an array.
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":{"address":"sp1xxx","start_height":0}}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":0.5,'
            '"history":[{"height":1,"tx_hash":"aa","tweak_key":"bb"}]}}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":1.0,'
            '"history":[{"height":2,"tx_hash":"cc","tweak_key":"dd"}]}}',
        ])
        scan_key, spend_pub = self._keys()
        history = client.scan(scan_key, spend_pub, 0)
        self.assertEqual([h["tx_hash"] for h in history], ["aa", "cc"])

    def test_accepts_positional_array_params(self):
        # Fallback shape for any server that follows the original spec.
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":{"address":"sp1xxx","start_height":0}}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '[{},1.0,[{"height":1,"tx_hash":"aa","tweak_key":"bb"}]]}',
        ])
        scan_key, spend_pub = self._keys()
        history = client.scan(scan_key, spend_pub, 0)
        self.assertEqual(history, [{"height": 1, "tx_hash": "aa", "tweak_key": "bb"}])

    def test_ignores_unrelated_methods(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":{"address":"sp1xxx","start_height":0}}',
            '{"method":"server.banner","params":["hi"]}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":1.0,'
            '"history":[{"height":1,"tx_hash":"aa","tweak_key":"bb"}]}}',
        ])
        scan_key, spend_pub = self._keys()
        history = client.scan(scan_key, spend_pub, 0)
        self.assertEqual(history, [{"height": 1, "tx_hash": "aa", "tweak_key": "bb"}])

    def test_completes_with_empty_final_chunk(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":{"address":"sp1xxx","start_height":0}}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":1.0,"history":[]}}',
        ])
        scan_key, spend_pub = self._keys()
        self.assertEqual(client.scan(scan_key, spend_pub, 0), [])

    def test_request_payload_carries_hex_keys(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"result":{"address":"sp1xxx","start_height":0}}',
            '{"method":"blockchain.silentpayments.subscribe","params":'
            '{"subscription":{},"progress":1.0,"history":[]}}',
        ])
        scan_key, spend_pub = self._keys()
        client.scan(scan_key, spend_pub, 12345)
        msg = json.loads(client._sock.sent[0].decode().strip())
        self.assertEqual(msg["method"], "blockchain.silentpayments.subscribe")
        self.assertEqual(msg["params"][0], scan_key.hex())
        self.assertEqual(msg["params"][1], spend_pub.hex())
        self.assertEqual(msg["params"][2], 12345)

    def test_raises_on_subscribe_error(self):
        client = _make_client([
            '{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"nope"}}',
        ])
        scan_key, spend_pub = self._keys()
        with self.assertRaises(RuntimeError):
            client.scan(scan_key, spend_pub, 0)


# ------------------ fee estimate ------------------

class _StubClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        return self.responses.get(method)


class FetchFeerateTests(unittest.TestCase):
    def test_converts_btc_per_kvb_to_sat_per_vb(self):
        # 0.00012 BTC/kvB = 12 sat/vB
        client = _StubClient({"blockchain.estimatefee": 0.00012})
        self.assertAlmostEqual(sp_scan.fetch_feerate(client), 12.0)

    def test_returns_none_on_negative_estimate(self):
        client = _StubClient({"blockchain.estimatefee": -1})
        self.assertIsNone(sp_scan.fetch_feerate(client))

    def test_returns_none_on_non_numeric(self):
        client = _StubClient({"blockchain.estimatefee": None})
        self.assertIsNone(sp_scan.fetch_feerate(client))


# ------------------ build_and_sign end-to-end ------------------

DEST_TAPROOT = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"


def _utxo(spend_priv_int, tweak_int, txid_hex, vout, value_sat):
    """Build a Utxo whose scriptPubKey is the canonical D for the given
    (spend_priv + tweak). Mirrors what sp_scan would emit."""
    d_int = (spend_priv_int + tweak_int) % sp_crypto.CURVE_N
    D_xonly = sp_crypto.output_x_only_pubkey(d_int)
    spk = b"\x51\x20" + D_xonly
    return sp_sign.Utxo(
        txid=txid_hex,
        vout=vout,
        value_sat=value_sat,
        script_pub_key=spk,
        priv_key_tweak=tweak_int,
    )


def _verify_tx_signatures(signed_hex, utxos):
    """Re-parse the signed tx, recompute the BIP-341 sighash for each input,
    and check the witness schnorr signature verifies against the input's
    x-only output key. Returns the parsed tx."""
    from bitcointx.core import CTransaction, CTxOut
    from bitcointx.core.script import CScript, SignatureHashSchnorr

    tx = CTransaction.deserialize(bytes.fromhex(signed_hex))
    spent_outputs = [CTxOut(u.value_sat, CScript(u.script_pub_key)) for u in utxos]
    for i, u in enumerate(utxos):
        stack = list(tx.wit.vtxinwit[i].scriptWitness.stack)
        if len(stack) != 1 or len(stack[0]) != 64:
            raise AssertionError(
                f"input {i} witness must be a single 64-byte schnorr sig, got {stack}"
            )
        sig = stack[0]
        sighash = SignatureHashSchnorr(tx, i, spent_outputs)
        x_only = u.script_pub_key[2:]
        if not PublicKeyXOnly(x_only).verify(sig, sighash):
            raise AssertionError(f"input {i} schnorr signature failed to verify")
    return tx


class BuildAndSignTests(unittest.TestCase):
    SPEND_PRIV_INT = 0x4242424242424242424242424242424242424242424242424242424242424242

    def test_single_input_signature_verifies(self):
        u = _utxo(self.SPEND_PRIV_INT, int("11" * 32, 16), "11" * 32, 7, 100_000)
        signed_hex = sp_sign.build_and_sign([u], DEST_TAPROOT, 500, self.SPEND_PRIV_INT)
        tx = _verify_tx_signatures(signed_hex, [u])
        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(tx.vin[0].prevout.n, 7)
        self.assertEqual(tx.vin[0].prevout.hash.hex(), "11" * 32)
        self.assertEqual(tx.vout[0].nValue, 99_500)

    def test_multiple_inputs_all_verify(self):
        u1 = _utxo(self.SPEND_PRIV_INT, int("11" * 32, 16), "11" * 32, 0, 50_000)
        u2 = _utxo(self.SPEND_PRIV_INT, int("22" * 32, 16), "22" * 32, 1, 80_000)
        signed_hex = sp_sign.build_and_sign([u1, u2], DEST_TAPROOT, 1_000, self.SPEND_PRIV_INT)
        tx = _verify_tx_signatures(signed_hex, [u1, u2])
        self.assertEqual(len(tx.vin), 2)
        self.assertEqual(tx.vout[0].nValue, 50_000 + 80_000 - 1_000)

    def test_dust_amount_raises(self):
        u = _utxo(self.SPEND_PRIV_INT, int("33" * 32, 16), "11" * 32, 0, 500)
        with self.assertRaises(ValueError):
            sp_sign.build_and_sign([u], DEST_TAPROOT, 400, self.SPEND_PRIV_INT)

    def test_mismatched_spend_priv_raises(self):
        u = _utxo(self.SPEND_PRIV_INT, int("44" * 32, 16), "11" * 32, 0, 50_000)
        wrong_spend_priv = (self.SPEND_PRIV_INT + 1) % sp_crypto.CURVE_N
        with self.assertRaises(ValueError) as ctx:
            sp_sign.build_and_sign([u], DEST_TAPROOT, 500, wrong_spend_priv)
        self.assertIn("does not match scriptPubKey", str(ctx.exception))


# ------------------ find_derivation_path ------------------

class FindDerivationPathTests(unittest.TestCase):
    def test_returns_none_for_random_seed(self):
        # Garbage seed cannot possibly match the canonical SP address.
        self.assertIsNone(
            sp_crypto.find_derivation_path(b"\x00" * 64, EXPECTED_SP_ADDRESS)
        )


# ------------------ -o / --output file helpers ------------------

PERM_MASK = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO  # low 9 bits


class OutputFileHelperTests(unittest.TestCase):
    """`-o keys.json` and `-o scanned.json` both go through small wrappers
    around os.open. Tests pin down the two properties the CLI promises:
    that secret-bearing files are created mode 0600, and that an existing
    file is truncated rather than appended to."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Pin umask so non-secret-mode assertions are deterministic across
        # developer machines (default is often 0o022 but not guaranteed).
        self._old_umask = os.umask(0)
        self.addCleanup(os.umask, self._old_umask)

    def _path(self, name):
        return os.path.join(self._tmp.name, name)

    def _mode(self, path):
        return os.stat(path).st_mode & PERM_MASK

    def test_derive_open_secret_file_writes_mode_0600(self):
        path = self._path("keys.json")
        with sp_derive.open_secret_file(path) as f:
            f.write("payload")
        self.assertEqual(self._mode(path), 0o600)
        with open(path) as f:
            self.assertEqual(f.read(), "payload")

    def test_derive_open_secret_file_truncates_existing(self):
        path = self._path("keys.json")
        with open(path, "w") as f:
            f.write("STALE-LONG-CONTENT")
        with sp_derive.open_secret_file(path) as f:
            f.write("new")
        with open(path) as f:
            self.assertEqual(f.read(), "new")

    def test_derive_open_secret_file_tightens_existing_perms(self):
        # If keys.json already exists with loose perms, opening via the
        # helper must not leave them loose. os.open with O_CREAT doesn't
        # chmod existing files, so the helper has to handle this itself.
        path = self._path("keys.json")
        with open(path, "w") as f:
            f.write("")
        os.chmod(path, 0o644)
        with sp_derive.open_secret_file(path) as f:
            f.write("x")
        self.assertEqual(self._mode(path), 0o600)

    def test_scan_open_output_file_secret_is_0600(self):
        path = self._path("scanned.json")
        with sp_scan.open_output_file(path, secret=True) as f:
            f.write("payload")
        self.assertEqual(self._mode(path), 0o600)

    def test_scan_open_output_file_nonsecret_is_0644(self):
        path = self._path("scanned.json")
        with sp_scan.open_output_file(path, secret=False) as f:
            f.write("payload")
        # umask was pinned to 0 in setUp, so the on-disk mode equals the
        # mode passed to os.open.
        self.assertEqual(self._mode(path), 0o644)

    def test_scan_open_output_file_truncates_existing(self):
        path = self._path("scanned.json")
        with open(path, "w") as f:
            f.write("STALE-LONG-CONTENT")
        with sp_scan.open_output_file(path, secret=False) as f:
            f.write("new")
        with open(path) as f:
            self.assertEqual(f.read(), "new")

    def test_scan_open_output_file_secret_tightens_existing_perms(self):
        path = self._path("scanned.json")
        with open(path, "w") as f:
            f.write("")
        os.chmod(path, 0o644)
        with sp_scan.open_output_file(path, secret=True) as f:
            f.write("x")
        self.assertEqual(self._mode(path), 0o600)


if __name__ == "__main__":
    unittest.main()
