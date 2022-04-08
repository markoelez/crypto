#!/usr/bin/env python3
import socket
import struct
import random
import hashlib
import base58
import binascii
import ecdsa


random.seed(1234)

def render(x):
    return int.from_bytes(x, 'little')

def checksum(x):
    x = sha256(x)
    x = sha256(x)
    return x[:4]

def hex(x):
    return binascii.hexlify(x).decode()

def b58(x):
    return base58.b58encode(x)

def b58_and_checksum(x):
    c = checksum(x)
    print('checksum:', hex(c))
    return b58(x + c)

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

def get_wif(private_key, compressed=False):
    x = b'\x80' + private_key
    if compressed: x += b'\x10'
    return b58_and_checksum(x).decode()

def get_public_addr(public_key):
    k = sha256(public_key)
    k = ripemd160(k)
    # version byte
    k = b'\x00' + k
    addr = b58(k + checksum(k))
    return addr.decode()

# generate private key
private_key = gen_private_key()
print('private_key:', hex(private_key))

# get public key
public_key = get_public_key(private_key)
print('public_key:', hex(public_key))

# get wif
wif = get_wif(private_key, compressed=True)
print('wif:', wif)

# get public address
public_addr = get_public_addr(public_key)
print('public_addr:', public_addr)
