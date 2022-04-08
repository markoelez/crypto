#!/usr/bin/env python3
import socket
import struct
import random
import hashlib
import base58
import binascii
import ecdsa
import qrcode


def checksum(x):
    x = sha256(x)
    x = sha256(x)
    return x[:4]

def hex(x):
    return binascii.hexlify(x).decode()

def b58(x):
    return base58.b58encode(x)

def b58_and_checksum(x):
    return b58(x + checksum(x))

def sha256(x):
    return hashlib.sha256(x).digest()

def ripemd160(x):
    m = hashlib.new('ripemd160')
    m.update(x)
    return m.digest()

def gen_private_key():
    # generate random 32 byte string
    k = bytes([random.randint(0, 256) for x in range(32)])
    return k
    #return hex(k)

def get_public_key(x):
    signing_key = ecdsa.SigningKey.from_string(x, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key().to_string()
    public_key = b'\x04' + verifying_key
    return public_key

def get_wif(private_key, test=True, compressed=False):
    if test:
        x = b'\xef' + private_key # testnet
    else:
        x = b'\x80' + private_key # mainnet
    if compressed: x += b'\x10'
    return b58_and_checksum(x).decode()

def get_public_addr(public_key, test=True):
    k = sha256(public_key)
    k = ripemd160(k)
    # version byte
    if test:
        k = b'\x6f' + k #testnet
    else:
        k = b'\x00' + k # mainnet
    return b58_and_checksum(k).decode()

def generate_keys(seed=1234):
    random.seed(seed)

    private_key = gen_private_key()
    public_key = get_public_key(private_key)
    wif = get_wif(private_key, compressed=False)
    public_addr = get_public_addr(public_key)

    return private_key, public_key, wif, public_addr

def gen_qrcode(addr, name='coin.png'):
    img = qrcode.make(addr)
    img.save(name)

if __name__ == '__main__':
    priv_key, pub_key, wif, pub_addr = generate_keys()

    print('private_key:', hex(priv_key))
    print('public_key:', hex(pub_key))
    print('wif:', wif)
    print('public_address:', pub_addr)
