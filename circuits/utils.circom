pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
// Convert 32 bytes into 4 64-bit numbers
template BytesToWords() {
    signal input in[32];
    
    signal output out[4];
    
    component bytes2Bits[32];
    for (var i = 0; i < 32; i++) {
        bytes2Bits[i] = Num2Bits(8);  // Each byte is 8 bits
        bytes2Bits[i].in <== in[i];
    }
    
    component bits2Num[4];
    for (var i = 0; i < 4; i++) {
        bits2Num[i] = Bits2Num(64);  // Each output is 64 bits
    }
    
    // Wire the bits from 8 bytes into each 64-bit number
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 8; j++) {  
            var byteIndex = i * 8 + j;  
            for (var k = 0; k < 8; k++) {  
                bits2Num[i].in[j * 8 + k] <== bytes2Bits[byteIndex].out[k];
            }
        }
        out[i] <== bits2Num[i].out;
    }
    
    // input checks
    for (var i = 0; i < 32; i++) {
        in[i] * (in[i] - 255) === 0;
    }
}

// 
template WordsToBytes() {
    signal input in[4];
    
    signal output out[32];
    
    component nums2Bits[4];
    for (var i = 0; i < 4; i++) {
        nums2Bits[i] = Num2Bits(64);
        nums2Bits[i].in <== in[i];
    }
    
    component bits2Bytes[32];
    for (var i = 0; i < 32; i++) {
        bits2Bytes[i] = Bits2Num(8);
    }
    
    // Wire the bits from each 64-bit number into bytes
    for (var i = 0; i < 4; i++) {  
        for (var j = 0; j < 8; j++) {  
            var byteIndex = i * 8 + j;  
            for (var k = 0; k < 8; k++) {  
                bits2Bytes[byteIndex].in[k] <== nums2Bits[i].out[j * 8 + k];
            }
        }
    }
    
    for (var i = 0; i < 32; i++) {
        out[i] <== bits2Bytes[i].out;
    }
    
    // output range checks
    for (var i = 0; i < 32; i++) {
        out[i] * (out[i] - 255) === 0;
    }
}

