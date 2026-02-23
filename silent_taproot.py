"""
silent_taproot.py

A small educational prototype showing how to build "silent payments" using Taproot-style key tweaks.

What it does
- derive_one_time_output(internal_xonly_hex, sender_ephemeral_priv_hex, network='mainnet') -> (xonly_hex, p2tr_address)
  - internal_xonly_hex: hex string of recipient's 32-byte x-only internal public key
  - sender_ephemeral_priv_hex: hex string of sender ephemeral private key (32 bytes)
  - returns the x-only public key for the one-time Taproot output and a bech32m encoded P2TR address

Why it matters
- Silent payments reduce address reuse and improve payer privacy: the sender can place funds at an output the recipient can detect and spend without prior communication of a fresh address.
- This example uses simple ECDH (x25519-like idea but on secp256k1) between sender ephemeral private key and recipient internal pubkey to derive a tweak scalar.
- It then follows the Taproot public key tweak: Q = P + hash(P||R)*G where R is the shared secret tweak. For simplicity we treat the shared secret as scalar directly (not recommended for production).

Usage examples are in README.md

Limitations and warnings (again)
- This is NOT production-grade. The scalar derivation is simplified. No user-specific domain separation string. No key parity handling for x-only to full pubkey conversions beyond the minimal.
- Use only for learning.

— Hal
"""

from hashlib import sha256
from coincurve import PrivateKey, PublicKey
import bech32

# Helper: convert 32-byte x-only pubkey hex to full compressed pubkey bytes
# We assume the x-only corresponds to an even-y public key (parity 0) for simplicity.
# A robust implementation must try both parities and follow BIP340 rules.

def xonly_to_compressed(xhex, even_y=True):
    x = bytes.fromhex(xhex)
    prefix = b"\x02" if even_y else b"\x03"
    return prefix + x

# Generate a random keypair (private key hex, x-only pubkey hex)
def generate_keypair():
    priv = PrivateKey()
    pub = priv.public_key.format(compressed=True)
    # pub[1:] is the x coordinate for compressed pubkey
    xonly = pub[1:].hex()
    return priv.to_hex(), xonly

# Derive one-time Taproot output pubkey from recipient internal xonly and sender ephemeral private key
# Returns x-only pubkey hex and bech32m P2TR address

def derive_one_time_output(internal_xonly_hex, sender_ephemeral_priv_hex, network='mainnet'):
    # reconstruct recipient full pubkey (assume even Y)
    rec_compressed = xonly_to_compressed(internal_xonly_hex, even_y=True)
    rec_pub = PublicKey(rec_compressed)

    # sender ephemeral private key
    eph_priv = PrivateKey(bytes.fromhex(sender_ephemeral_priv_hex))
    # ECDH: shared point = eph_priv * rec_pub
    shared = rec_pub.multiply(eph_priv.secret)
    shared_bytes = PublicKey(shared).format(compressed=True)

    # derive tweak scalar = sha256(shared_bytes)
    tweak = int.from_bytes(sha256(shared_bytes).digest(), 'big') % PublicKey.curve.order

    # taproot tweak: Q = P + tweak*G
    P_point = rec_pub.format(compressed=False)
    P = PublicKey(P_point)

    tweak_point = PublicKey.from_valid_secret((tweak.to_bytes(32, 'big'))).public_key
    tweaked_point = PublicKey(P_point).add(tweak_point.format(compressed=False))
    tweaked_compressed = tweaked_point.format(compressed=True)

    # extract x-only
    xonly = tweaked_compressed[1:].hex()

    # build bech32m P2TR address: witness version 1, 32-byte output key
    witver = 1
    witprog = bytes.fromhex(xonly)
    if network == 'mainnet':
        hrp = 'bc'
    else:
        hrp = 'tb'

    # convert to 5-bit words
    converted = bech32.convertbits(witprog, 8, 5)
    bech = bech32.bech32_encode(hrp, [witver] + converted, Encoding=bech32.Encoding.BECH32M)

    return xonly, bech

# Simple test when run as script
if __name__ == '__main__':
    rec_priv, rec_xonly = generate_keypair()
    eph_priv, eph_xonly = generate_keypair()
    print('Recipient internal xonly:', rec_xonly)
    print('Sender ephemeral priv (hex):', eph_priv)
    xonly, addr = derive_one_time_output(rec_xonly, eph_priv, network='testnet')
    print('One-time output xonly:', xonly)
    print('P2TR address:', addr)
