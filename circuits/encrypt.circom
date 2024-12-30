pragma circom 2.1.9;

include "./ecdsa/circuits/secp256k1.circom";
include "./hkdf/circuits/hkdf.circom";
include "./hmac/circuits/hmac.circom";
include "./aes-circom/circuits/ctr.circom";
include "./utils.circom";

template Encrypt(npt,ns1,ns2,niv){
  signal input r[32];
  signal input x[32];
  signal input y[32];
  signal input pt[npt];
  signal input iv[16];
  signal input s1[ns1];
  signal input s2[ns2];

  signal output pubkey[2][4];
  signal output ct[npt];
  signal output hmac[32];

  component BytesToWords[3];
  BytesToWords[0].in <== r;
  BytesToWords[1].in <== x;
  BytesToWords[2].in <== y;

  component SK = GenSharedKey();
  SK.r <== BytesToWords[0].out;
  SK.px <== BytesToWords[1].out;
  SK.py <== BytesToWords[2].out;

  component KG = KeyGen(ns1);
  KG.info <== s1;
  KG.key <== SK.out;


  component AESCTR = EncryptCTR(npt,4);
  AESCTR.plainText <== pt;
  AESCTR.iv <== iv;
  AESCTR.key <== kg.out[0];

  component HMAC = HmacSha256(npt+ns2,16);
  HMAC.key <== kg.out[1];
  for (var i = 0; i < npt; i++) {
    HMAC.message[i] <== pt[i];
  }
  for (var i = 0; i < ns2; i++) {
    HMAC.message[npt+i] <== s2[i];
  }

  component PRIV2PUB = ECDSAPrivToPub(64,4);
  PRIV2PUB.privkey[0] <== BytesToWords[0].out;

  pubkey <== PRIV2PUB.pubkey;
  ct <== AESCTR.cipher;
  hmac <== HMAC.hmac;

  // decryption needs pubkey.x | pubkey.y | iv | ct | hmac
}

template GenSharedKey(){
  signal input r[4];
  signal input px[4];
  signal input py[4];

  component scalarMul = Secp256k1ScalarMult(64,4);
  scalarMul.scalar <== r;
  scalarMul.point[0] <== px;
  scalarMul.point[1] <== py;


  component WordsToBytes;
  WordsToBytes.in <== scalarMul.out[0];
  
  signal output out[32];
}

template KeyGen(ni){
  signal input info[i];
  signal input key[32];

  signal output out[2][16];

  component HKDF = HKDFSha256(0,ni,32,2,16);

  HKDF.info <== info;
  HKDF.key <== key;

  out <== HKDF.out;
}
