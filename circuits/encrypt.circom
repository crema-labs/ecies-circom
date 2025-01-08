pragma circom 2.1.9;

include "./ecdsa/circuits/ec/curve.circom";
include "./hkdf.circom";
include "./hmac.circom";
include "./aes-circom/circuits/ctr.circom";
include "./utils.circom";

template Encrypt(npt,ns1,ns2){
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

  component BytesToStrides[3];
  for (var i = 0; i < 3; i++) {
    BytesToStrides[i] = BytesToStrides();
  }
  BytesToStrides[0].in <== r;
  BytesToStrides[1].in <== x;
  BytesToStrides[2].in <== y;

  component SK = GenSharedKey();
  SK.r <== BytesToStrides[0].out;
  SK.px <== BytesToStrides[1].out;
  SK.py <== BytesToStrides[2].out;

  component KG = KeyGen(ns1);
  KG.info <== s1;
  KG.key <== SK.out;

  component AESCTR = EncryptCTR(npt,4);
  AESCTR.plainText <== pt;
  AESCTR.iv <== iv;
  AESCTR.key <== KG.out[0];

  component HMAC = HmacSha256(16+npt+ns2,16);
  HMAC.key <== KG.out[1];
  for (var i = 0; i < 16; i++) {
    HMAC.message[i] <== iv[i];
  }
  for (var i = 0; i < npt; i++) {
    HMAC.message[16+i] <== AESCTR.cipher[i];
  }
  for (var i = 0; i < ns2; i++) {
    HMAC.message[16+npt+i] <== s2[i];
  }

  component PRIV2PUB = EllipicCurveScalarGeneratorMultiplicationOptimised(64,4, [0,0,0,0], [7,0,0,0], [18446744069414583343, 18446744073709551615, 18446744073709551615, 18446744073709551615]);
  PRIV2PUB.scalar <== BytesToStrides[0].out;
  PRIV2PUB.dummy <== 0;

  pubkey <== PRIV2PUB.out;
  ct <== AESCTR.cipher;
  hmac <== HMAC.hmac;

  // decryption needs pubkey.x | pubkey.y | iv | ct | hmac
}

template GenSharedKey(){
  signal input r[4];
  signal input px[4];
  signal input py[4];

  signal output out[32];

  component scalarMul = EllipticCurvePipingerMult(64, 4, [0,0,0,0], [7,0,0,0], [18446744069414583343, 18446744073709551615, 18446744073709551615, 18446744073709551615], 4);
  scalarMul.scalar <== r;
  scalarMul.in[0] <== px;
  scalarMul.in[1] <== py;
  scalarMul.dummy <== 0;


  component StridesToBytes = StridesToBytes();
  StridesToBytes.in <== scalarMul.out[0];
  
  for(var i=0;i<32;i++){
    out[i] <== StridesToBytes.out[31-i];
  }
}

template KeyGen(ni){
  signal input info[ni];
  signal input key[32];

  signal output out[2][16];

  component HKDF = HKDFSha256(0,ni,32,2,16);

  HKDF.info <== info;
  HKDF.key <== key;

  out <== HKDF.out;
}
