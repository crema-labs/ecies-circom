pragma circom 2.1.9;

include "./hmac.circom";

// s : salt length
// i : info length
// k : key length
// m : number of keys to extract
// n : key length
template HKDFSha256(s,i,k,m,n){
  signal input salt[s];
  signal input info[i];
  signal input key[k];

  signal output out[m][n];

  component extract = Extract(s, k);
  extract.salt <== salt;
  extract.key <== key;

  component expand = Expand(i, 32, m, n);
  expand.info <== info;
  expand.key <== extract.out;

  out <== expand.out;
}

// s : salt length
// k : key length
// out : 32 bytes from sha256 hmac
template Extract(s,k){
  signal input salt[s];
  signal input key[k];

  component hmac = HmacSha256(k,s);
  signal output out[32];

  hmac.message <== key;
  hmac.key <== salt;

  out <== hmac.hmac;
}

// i : info length
// k : key length
// m : number of keys to extract
// n : key length
template Expand(i,k,m,n){
  signal input info[i];
  signal input key[k];
  
  var size = 32 + i + 1; // 32 bytes for hmac, i bytes for info, 1 byte for counter

  // hash size is 32 bytes 
  var rounds = (m*n)\(32);
  rounds = (rounds * 32) < (m*n) ? rounds + 1 : rounds;


  component hmac[rounds];

  signal expandedKeys [rounds][32];
  signal output out[m][n];

  hmac[0] = HmacSha256(i+1,k);
  hmac[0].key <== key; 
  for (var j = 0; j < i; j++){
      hmac[0].message[j] <== info[j];
  }
  hmac[0].message[i] <== 1; // here counter is byte(1)
  expandedKeys[0] <== hmac[0].hmac;
  
  var counter = 2; // counter is byte(2)

  for(var j = 1; j < rounds; j++){
    hmac[j] = HmacSha256(size, k);
    for (var o = 0; o < 32; o++){
      hmac[j].message[o] <== expandedKeys[j-1][o];
    }
    for (var o = 0; o < i; o++){
      hmac[j].message[32+o] <== info[o];
    }
    hmac[j].message[32+i] <== counter;
    hmac[j].key <== key;
    expandedKeys[j] <== hmac[j].hmac;
    counter = counter + 1;
  }

  var byteIndex = 0;
  for (var j = 0; j < m; j++) {
    for (var o = 0; o < n; o++) {
      out[j][o] <== expandedKeys[byteIndex \ 32][byteIndex % 32];
      byteIndex++;
    }
  }
}


