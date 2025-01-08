pragma circom 2.1.9;

include "./ecdsa-0xparc/circuits/secp256k1.circom"; // For secp256k1 elliptic curve operations
include "./ecdsa-0xparc/circuits/ecdsa.circom";     // For ECDSA operations
include "./hkdf.circom";                            // For HKDF key derivation
include "./hmac.circom";                            // For HMAC authentication
include "./aes-circom/circuits/ctr.circom";         // For AES-CTR encryption
include "./utils.circom";                           // For utility functions

// Main encryption template
// Parameters:
// - npt: length of plaintext
// - ns1: length of first salt
// - ns2: length of second salt
template Encrypt(npt,ns1,ns2){
  // Input signals
  signal input r[32];     // Random value (private key)
  signal input x[32];     // X coordinate of recipient's public key
  signal input y[32];     // Y coordinate of recipient's public key
  signal input pt[npt];   // Plaintext to encrypt
  signal input iv[16];    // Initialization vector for AES-CTR
  signal input s1[ns1];   // First salt for key derivation
  signal input s2[ns2];   // Second salt for HMAC

  // Output signals
  signal output pubkey[2][4];  // Sender's public key
  signal output ct[npt];       // Ciphertext
  signal output hmac[32];      // HMAC for authentication

  // Convert byte arrays to stride format for elliptic curve operations
  component BytesToStrides[3];
  for (var i = 0; i < 3; i++) {
    BytesToStrides[i] = BytesToStrides();
  }
  BytesToStrides[0].in <== r;  // Convert private key
  BytesToStrides[1].in <== x;  // Convert public key X
  BytesToStrides[2].in <== y;  // Convert public key Y

  // Generate shared secret using ECDH
  component SK = GenSharedKey();
  SK.r <== BytesToStrides[0].out;   // Private key
  SK.px <== BytesToStrides[1].out;  // Public key X
  SK.py <== BytesToStrides[2].out;  // Public key Y

  // Derive encryption and HMAC keys from shared secret
  component KG = KeyGen(ns1);
  KG.info <== s1;             // Salt for key derivation
  KG.key <== SK.out;         // Shared secret

  // Encrypt plaintext using AES-CTR
  component AESCTR = EncryptCTR(npt,4);
  AESCTR.plainText <== pt;    // Input plaintext
  AESCTR.iv <== iv;          // Initialization vector
  AESCTR.key <== KG.out[0];  // Encryption key

  // Generate HMAC for authentication
  component HMAC = HmacSha256(16+npt+ns2,16);
  HMAC.key <== KG.out[1];    // HMAC key
  // Concatenate IV, ciphertext, and salt for HMAC input
  for (var i = 0; i < 16; i++) {
    HMAC.message[i] <== iv[i];
  }
  for (var i = 0; i < npt; i++) {
    HMAC.message[16+i] <== AESCTR.cipher[i];
  }
  for (var i = 0; i < ns2; i++) {
    HMAC.message[16+npt+i] <== s2[i];
  }

  // Generate sender's public key from private key
  component PRIV2PUB = ECDSAPrivToPub(64,4);
  PRIV2PUB.privkey <== BytesToStrides[0].out;

  // Assign outputs
  pubkey <== PRIV2PUB.pubkey;
  ct <== AESCTR.cipher;
  hmac <== HMAC.hmac;
  // Note: For decryption, recipient needs: pubkey.x | pubkey.y | iv | ct | hmac
}

// Generate shared secret using ECDH key exchange
template GenSharedKey(){
  signal input r[4];    // Private key in stride format
  signal input px[4];   // Public key X coordinate in stride format
  signal input py[4];   // Public key Y coordinate in stride format
  signal output out[32]; // Shared secret in bytes

  // Perform scalar multiplication for ECDH
  component scalarMul = Secp256k1ScalarMult(64,4);
  scalarMul.scalar <== r;
  scalarMul.point[0] <== px;
  scalarMul.point[1] <== py;

  // Convert result back to bytes
  component StridesToBytes = StridesToBytes();
  StridesToBytes.in <== scalarMul.out[0];
  
  // Reverse byte order for big-endian representation
  for(var i=0;i<32;i++){
    out[i] <== StridesToBytes.out[31-i];
  }
}

// Generate encryption and HMAC keys from shared secret
template KeyGen(ni){
  signal input info[ni];     // Salt for key derivation
  signal input key[32];      // Input key (shared secret)
  signal output out[2][16];  // Two 16-byte keys: [encryption_key, hmac_key]

  // Use HKDF to derive two keys
  component HKDF = HKDFSha256(0,ni,32,2,16);
  HKDF.info <== info;
  HKDF.key <== key;
  out <== HKDF.out;
}