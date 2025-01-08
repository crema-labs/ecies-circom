# ECIES Encryption

This repository contains a Circom implementation of a hybrid encryption scheme combining ECDSA, AES-CTR, and HMAC-SHA256 for secure message encryption and authentication.

## Overview

The hybrid encryption scheme provides confidentiality and authenticity by combining:
- ECDH (Elliptic Curve Diffie-Hellman) for key exchange
- HKDF-SHA256 for key derivation
- AES-CTR for encryption
- HMAC-SHA256 for authentication

The implementation follows cryptographic standards and best practices for hybrid encryption schemes.

## Circuit Implementation

The main circuit components are:

### Encrypt Template

The primary encryption template that orchestrates the entire encryption process:

```circom
template Encrypt(npt, ns1, ns2)
```

Parameters:
- `npt`: Length of plaintext
- `ns1`: Length of first salt (for key derivation)
- `ns2`: Length of second salt (for authentication)

### GenSharedKey Template

Implements ECDH key exchange using secp256k1:

```circom
template GenSharedKey()
```

Generates a shared secret from:
- Private key (r)
- Public key coordinates (px, py)

### KeyGen Template

Derives encryption and HMAC keys using HKDF-SHA256:

```circom
template KeyGen(ni)
```

Parameters:
- `ni`: Length of info/salt for key derivation

## Dependencies

- [circom-ecdsa](https://github.com/crema-labs/circom-ecdsa): ECDSA and secp256k1 operations
- [hmac-circom](https://github.com/crema-labs/hmac-circom): HMAC-SHA256 implementation
- [hkdf-circom](https://github.com/crema-labs/hkdf-circom): HKDF key derivation
- [aes-circom](https://github.com/crema-labs/aes-circom): AES-CTR mode encryption

## Security Properties

The circuit provides:
1. **Confidentiality**: Using AES-CTR encryption
2. **Authentication**: Using HMAC-SHA256
3. **Forward Secrecy**: Using ephemeral ECDH key exchange
4. **Public Key Authentication**: Including sender's public key

## Message Format

The encrypted message format is:
```
pubkey.x | pubkey.y | iv | ciphertext | hmac
```

Where:
- `pubkey`: Sender's public key (for verification)
- `iv`: 16-byte initialization vector
- `ciphertext`: AES-CTR encrypted message
- `hmac`: Authentication tag

## Test Results

| Test Case | Constraints | Plaintext Size | Salt1 Size | Salt2 Size | Time (s) |
|-----------|------------|----------------|------------|------------|----------|
| Basic     | TBD        | 32            | 16         | 16         | TBD      |


## Usage

To run the tests:

```bash
yarn test
```

## References :
- [NIST SP 800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
- https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption
- https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/README
