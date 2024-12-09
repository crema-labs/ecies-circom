pragma circom 2.1.5;

bus Result(n){
  signal output Rx[32];
  signal output Ry[32];
  signal output ct[n];
  signal output hmac[32];
}

bus Point(){
  signal output x[32];
  signal output y[32];
}

template Encrypt(n){
  signal input r;
  public input n;
  signal input pt[n];
  signal output x[32];
  signal output y[32];

  component generateKey = KeyGen();

  signal output Rx[32];
  signal output Ry[32];
  signal output ct[n];
  signal output hmac[32];
}

template KeyGen(){
  signal input  r;
  
  signal output key[32];
}

