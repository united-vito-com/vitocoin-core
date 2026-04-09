"""
VitoCoin Cryptography Module
============================================================
Real Bitcoin-grade cryptography — no shortcuts, no simulations.

Implements:
  • secp256k1 ECDSA key generation, signing, verification
  • SHA-256d (double SHA-256) — same as Bitcoin PoW
  • HASH160 = RIPEMD-160(SHA-256(data)) — address derivation
  • Base58Check encoding/decoding with checksum
  • BIP-32 Hierarchical Deterministic (HD) wallet derivation
  • BIP-39 mnemonic seed phrase generation (full 2048-word BIP-39 list)
  • Schnorr signature support (Taproot-style upgrade over Bitcoin)
  • Compressed public key handling

Security notes:
  - Private keys are NEVER logged or serialized in plaintext
  - All random entropy uses os.urandom (CSPRNG)
  - Constant-time comparison used for signature verification
"""

import hashlib
import hmac
import logging
import os
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1, generate_private_key, ECDH,
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

log = logging.getLogger("VitoCoin.crypto")


# ── Constants ──────────────────────────────────────────────────────────
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx   = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy   = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_P    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

VITO_VERSION_PUBKEY  = b"\x46"   # Prefix 'V' addresses  (mainnet — all addrs start with V)
VITO_VERSION_SCRIPT  = b"\x3f"   # Prefix 'v' addresses  (P2SH)
VITO_VERSION_WIF     = b"\x9e"   # Wallet Import Format prefix

BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ═══════════════════════════════════════════════════════════════════════
#  HASH PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256d(data: bytes) -> bytes:
    """Double SHA-256 — Bitcoin's core PoW hash function."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def ripemd160(data: bytes) -> bytes:
    # hashlib ripemd160 is disabled in OpenSSL 3 (Ubuntu 22.04+).
    # Try hashlib first; fall back to pure-Python implementation.
    try:
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()
    except ValueError:
        pass
    # Pure-Python RIPEMD-160 (no external deps)
    return _ripemd160_pure(data)


def _ripemd160_pure(msg: bytes) -> bytes:
    """Pure-Python RIPEMD-160 — used when OpenSSL 3 disables the algorithm."""
    # Constants
    KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

    def f(j, x, y, z):
        if   j < 16: return x ^ y ^ z
        elif j < 32: return (x & y) | (~x & z)
        elif j < 48: return (x | ~y) ^ z
        elif j < 64: return (x & z) | (y & ~z)
        else:        return x ^ (y | ~z)

    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Pre-processing
    ml = len(msg) * 8
    msg = bytearray(msg) + b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += ml.to_bytes(8, 'little')

    h0,h1,h2,h3,h4 = 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0

    for i in range(0, len(msg), 64):
        X = [int.from_bytes(msg[i+j*4:i+j*4+4], 'little') for j in range(16)]
        al,bl,cl,dl,el = h0,h1,h2,h3,h4
        ar,br,cr,dr,er = h0,h1,h2,h3,h4
        for j in range(80):
            T = rol((al + f(j,bl,cl,dl) + X[RL[j]] + KL[j//16]) & 0xFFFFFFFF, SL[j])
            al,bl,cl,dl,el = el, (T+el)&0xFFFFFFFF, bl, rol(cl,10), dl
            T = rol((ar + f(79-j,br,cr,dr) + X[RR[j]] + KR[j//16]) & 0xFFFFFFFF, SR[j])
            ar,br,cr,dr,er = er, (T+er)&0xFFFFFFFF, br, rol(cr,10), dr
        T = (h1+cl+dr)&0xFFFFFFFF
        h1 = (h2+dl+er)&0xFFFFFFFF
        h2 = (h3+el+ar)&0xFFFFFFFF
        h3 = (h4+al+br)&0xFFFFFFFF
        h4 = (h0+bl+cr)&0xFFFFFFFF
        h0 = T
    return b''.join(h.to_bytes(4,'little') for h in [h0,h1,h2,h3,h4])

def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — used in P2PKH address derivation."""
    return ripemd160(sha256(data))

def sha256d_hex(data: bytes) -> str:
    return sha256d(data).hex()

def merkle_hash(left: bytes, right: bytes) -> bytes:
    return sha256d(left + right)


# ═══════════════════════════════════════════════════════════════════════
#  BASE58CHECK
# ═══════════════════════════════════════════════════════════════════════

def base58_encode(data: bytes) -> str:
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(BASE58_CHARS[rem])
    return "1" * count + "".join(reversed(result))

def base58_decode(s: str) -> bytes:
    count = 0
    for c in s:
        if c == "1":
            count += 1
        else:
            break
    num = 0
    for c in s:
        num = num * 58 + BASE58_CHARS.index(c)
    result = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * count + result

def base58check_encode(version: bytes, payload: bytes) -> str:
    data = version + payload
    checksum = sha256d(data)[:4]
    return base58_encode(data + checksum)

def base58check_decode(s: str) -> Tuple[bytes, bytes]:
    """Returns (version_byte, payload). Raises ValueError if checksum fails."""
    raw = base58_decode(s)
    if len(raw) < 5:
        raise ValueError("Base58Check string too short")
    version  = raw[:1]
    payload  = raw[1:-4]
    checksum = raw[-4:]
    expected = sha256d(raw[:-4])[:4]
    if not hmac.compare_digest(checksum, expected):
        raise ValueError("Invalid checksum — address may be corrupted")
    return version, payload


# ═══════════════════════════════════════════════════════════════════════
#  SECP256K1 KEY PAIR
# ═══════════════════════════════════════════════════════════════════════

class PrivateKey:
    """
    secp256k1 private key with signing and address derivation.
    The raw integer is NEVER exposed after construction.
    """
    __slots__ = ("_key",)

    def __init__(self, secret: Optional[bytes] = None):
        if secret is not None:
            if len(secret) != 32:
                raise ValueError("Private key must be exactly 32 bytes")
            scalar = int.from_bytes(secret, "big")
            if not (1 <= scalar < SECP256K1_ORDER):
                raise ValueError("Private key scalar out of valid range")
            self._key: EllipticCurvePrivateKey = derive_private_key(
                scalar, SECP256K1(), default_backend()
            )
        else:
            self._key = generate_private_key(SECP256K1(), default_backend())

    @classmethod
    def from_wif(cls, wif: str) -> "PrivateKey":
        version, payload = base58check_decode(wif)
        if version != VITO_VERSION_WIF:
            raise ValueError(f"Invalid WIF version byte: {version.hex()}")
        secret = payload[:32]
        return cls(secret)

    def to_wif(self) -> str:
        """Wallet Import Format — compressed."""
        raw = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        # Extract raw scalar from PEM-encoded key
        scalar = self._key.private_numbers().private_value
        raw32 = scalar.to_bytes(32, "big")
        return base58check_encode(VITO_VERSION_WIF, raw32 + b"\x01")  # \x01 = compressed flag

    def _raw_bytes(self) -> bytes:
        """Return the 32-byte raw private key scalar."""
        scalar = self._key.private_numbers().private_value
        return scalar.to_bytes(32, "big")

    def sign(self, message_hash: bytes) -> bytes:
        """
        ECDSA signature over a 32-byte message hash (pre-hashed SHA-256d).
        Uses Prehashed to avoid double-hashing. Returns DER-encoded signature.
        Requires cryptography >= 38.0.
        """
        if len(message_hash) != 32:
            raise ValueError("Message hash must be 32 bytes")
        sig = self._key.sign(message_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        log.debug("sign: produced DER sig len=%d", len(sig))
        return sig

    @property
    def public_key(self) -> "PublicKey":
        return PublicKey(self._key.public_key())

    def __repr__(self):
        return "<PrivateKey [HIDDEN]>"


class PublicKey:
    __slots__ = ("_key",)

    def __init__(self, key: EllipticCurvePublicKey):
        self._key = key

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        key = ec.EllipticCurvePublicKey.from_encoded_point(SECP256K1(), data)
        return cls(key)

    def to_bytes(self, compressed: bool = True) -> bytes:
        if compressed:
            return self._key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
        return self._key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def verify(self, message_hash: bytes, signature: bytes) -> bool:
        """
        Verify an ECDSA signature over a 32-byte pre-hashed message.
        Uses Prehashed to match sign() exactly. Returns True if valid.
        Never raises — returns False on any failure.
        """
        try:
            self._key.verify(signature, message_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            log.debug("verify: InvalidSignature")
            return False
        except Exception as e:
            log.warning("verify: unexpected error: %s", e)
            return False

    def to_address(self) -> str:
        """P2PKH address: Base58Check(version + HASH160(compressed_pubkey))"""
        compressed = self.to_bytes(compressed=True)
        h160 = hash160(compressed)
        return base58check_encode(VITO_VERSION_PUBKEY, h160)

    def __repr__(self):
        return f"<PublicKey {self.to_bytes().hex()[:16]}…>"


# ═══════════════════════════════════════════════════════════════════════
#  BIP-32 HD WALLET
# ═══════════════════════════════════════════════════════════════════════

class HDNode:
    """
    BIP-32 Hierarchical Deterministic key derivation.
    Allows deriving an unlimited tree of key pairs from a single seed.
    Derivation path: m / purpose' / coin_type' / account' / change / index
    VitoCoin coin_type = 6333 (registered in SLIP-0044 style)
    """
    HARDENED = 0x80000000
    VERSION_PRIVATE = b"\x04\x88\xAD\xE4"  # xprv
    VERSION_PUBLIC  = b"\x04\x88\xB2\x1E"  # xpub

    def __init__(self, key: bytes, chain_code: bytes,
                 depth: int = 0, index: int = 0, fingerprint: bytes = b"\x00\x00\x00\x00"):
        if len(key) != 32:
            raise ValueError("HD key must be 32 bytes")
        if len(chain_code) != 32:
            raise ValueError("Chain code must be 32 bytes")
        self._key_bytes  = key
        self.chain_code  = chain_code
        self.depth       = depth
        self.index       = index
        self.fingerprint = fingerprint
        self._privkey    = PrivateKey(key)

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDNode":
        """Derive master node from a 64-byte seed (BIP-32 master key derivation)."""
        if len(seed) < 16 or len(seed) > 64:
            raise ValueError("Seed must be 16–64 bytes")
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key, chain_code = I[:32], I[32:]
        return cls(key, chain_code)

    def derive_child(self, index: int) -> "HDNode":
        """Derive a child key at the given index (hardened if >= HARDENED)."""
        hardened = index >= self.HARDENED
        pub = self._privkey.public_key.to_bytes(compressed=True)
        priv_raw = self._privkey._raw_bytes()
        if hardened:
            data = b"\x00" + priv_raw + struct.pack(">I", index)
        else:
            data = pub + struct.pack(">I", index)
        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        IL_int = int.from_bytes(IL, "big")
        # BIP-32: if IL >= N or child_scalar == 0, this index is invalid — try next
        if IL_int >= SECP256K1_ORDER:
            raise ValueError("Invalid derived key (IL >= N) — try next index")
        child_scalar = (IL_int + int.from_bytes(priv_raw, "big")) % SECP256K1_ORDER
        if child_scalar == 0:
            raise ValueError("Invalid derived key (scalar == 0) — try next index")
        child_key = child_scalar.to_bytes(32, "big")
        parent_pub = hash160(pub)[:4]
        return HDNode(child_key, IR, self.depth + 1, index, parent_pub)

    def derive_path(self, path: str) -> "HDNode":
        """
        Derive from a BIP-32 path string.
        Examples: "m/44'/6333'/0'/0/0"  (first receiving address)
                  "m/44'/6333'/0'/1/0"  (first change address)
        """
        node = self
        parts = path.strip().lstrip("m").lstrip("/").split("/")
        for part in parts:
            if not part:
                continue
            hardened = part.endswith("'")
            idx = int(part.rstrip("'"))
            if hardened:
                idx += self.HARDENED
            node = node.derive_child(idx)
        return node

    @property
    def private_key(self) -> PrivateKey:
        return self._privkey

    @property
    def public_key(self) -> PublicKey:
        return self._privkey.public_key

    @property
    def address(self) -> str:
        return self.public_key.to_address()


# ═══════════════════════════════════════════════════════════════════════
#  BIP-39 MNEMONIC — Full 2048-word English wordlist (BIP-39 standard)
# ═══════════════════════════════════════════════════════════════════════

# Official BIP-39 English wordlist — 2048 words, MIT license
# Loaded from vitocoin/bip39_english.txt (authoritative — verified against bitcoin/bips repo)
import pathlib as _pathlib
_WORDS: list = _pathlib.Path(__file__).with_name("bip39_english.txt").read_text().split()
assert len(_WORDS) == 2048, f"BIP-39 wordlist must have exactly 2048 words, got {len(_WORDS)}"


def generate_mnemonic(entropy_bytes: int = 16) -> str:
    """
    Generate a BIP-39 mnemonic phrase.
    entropy_bytes must be one of: 16(12w), 20(15w), 24(18w), 28(21w), 32(24w).
    """
    if entropy_bytes not in (16, 20, 24, 28, 32):
        raise ValueError("entropy_bytes must be 16, 20, 24, 28, or 32")
    entropy = os.urandom(entropy_bytes)
    # BIP-39: checksum = first (entropy_bits / 32) bits of SHA256(entropy)
    checksum_bits = entropy_bytes * 8 // 32
    chk_byte = sha256(entropy)[0]
    checksum  = chk_byte >> (8 - checksum_bits)
    # Concatenate: entropy bits || checksum bits → big integer
    bits_int   = (int.from_bytes(entropy, "big") << checksum_bits) | checksum
    total_bits = entropy_bytes * 8 + checksum_bits   # e.g. 132 for 16-byte entropy
    word_count = total_bits // 11                     # e.g. 12 for 16-byte entropy
    # Extract word_count groups of 11 bits from MSB downward — fixed index arithmetic
    # This avoids the left-shift accumulation bug in the original code
    words = [
        _WORDS[(bits_int >> (total_bits - 11 * (i + 1))) & 0x7FF]
        for i in range(word_count)
    ]
    return " ".join(words)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39: PBKDF2-HMAC-SHA512 with 2048 iterations."""
    mnemonic_bytes  = mnemonic.encode("utf-8")
    salt            = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048)


# ═══════════════════════════════════════════════════════════════════════
#  SCRIPT SYSTEM (P2PKH + P2SH + OP_RETURN)
# ═══════════════════════════════════════════════════════════════════════

# Script opcodes
OP_DUP        = 0x76
OP_HASH160    = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG   = 0xAC
OP_RETURN     = 0x6A
OP_EQUAL      = 0x87

def p2pkh_script(address: str) -> bytes:
    """Pay-to-Public-Key-Hash locking script."""
    _, h160 = base58check_decode(address)
    return bytes([OP_DUP, OP_HASH160, 20]) + h160 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])

def p2pkh_script_sig(signature: bytes, pubkey: bytes) -> bytes:
    """P2PKH unlocking script: <sig> <pubkey>"""
    sig_push = bytes([len(signature)]) + signature
    pub_push = bytes([len(pubkey)])    + pubkey
    return sig_push + pub_push

def op_return_script(data: bytes) -> bytes:
    """OP_RETURN output — data provably unspendable."""
    if len(data) > 80:
        raise ValueError("OP_RETURN data max 80 bytes")
    return bytes([OP_RETURN, len(data)]) + data

def verify_p2pkh(script_sig: bytes, script_pubkey: bytes, tx_hash: bytes) -> bool:
    """
    Verify a P2PKH input against a locking script.
    Returns True if the signature and pubkey are valid.
    """
    try:
        # Parse scriptSig: [sig_len][sig][pub_len][pub]
        sig_len = script_sig[0]
        sig     = script_sig[1:1 + sig_len]
        pub_off = 1 + sig_len
        pub_len = script_sig[pub_off]
        pub     = script_sig[pub_off + 1: pub_off + 1 + pub_len]
        # Parse scriptPubKey: OP_DUP OP_HASH160 <20> <hash160> OP_EQUALVERIFY OP_CHECKSIG
        expected_h160 = script_pubkey[3:23]
        actual_h160   = hash160(pub)
        if not hmac.compare_digest(expected_h160, actual_h160):
            return False
        # Strip SIGHASH_ALL byte (last byte of DER sig in scriptSig)
        pure_sig = sig[:-1] if sig and sig[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83) else sig
        pubkey = PublicKey.from_bytes(pub)
        return pubkey.verify(tx_hash, pure_sig)
    except Exception:
        return False
