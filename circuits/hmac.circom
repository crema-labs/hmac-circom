pragma circom 2.1.8;


include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "sha256Hasher.circom";

template HmacSha256(n, k) {
    var blockSize = 64;
    signal input message[n];
    signal input key[k];
    signal output hmac[32];

    component keyPrep = KeyPrep(k);
    keyPrep.in <== key;

    signal keyOut[64] <== keyPrep.key;

    component innerKeyXOR[blockSize];
    component outerKeyXOR[blockSize];

    for (var i = 0; i < blockSize; i++) {
        innerKeyXOR[i] = XorByte();
        innerKeyXOR[i].a <== keyOut[i];
        innerKeyXOR[i].b <== 0x36;

        outerKeyXOR[i] = XorByte();
        outerKeyXOR[i].a <== keyOut[i];
        outerKeyXOR[i].b <== 0x5c;
    }

    signal innerHashIn[blockSize + n];

    for (var i = 0; i < blockSize; i++) {
        innerHashIn[i] <== innerKeyXOR[i].out;
    }
    for (var i = 0; i < n; i++) {
        innerHashIn[blockSize + i] <== message[i];
    }

    component innerHash = Sha256Bytes(blockSize + n);

    for (var i = 0; i < blockSize + n; i++) {
        innerHash.in[i] <== innerHashIn[i];
    }

    signal outerHashIn[blockSize + 32];

    for (var i = 0; i < blockSize; i++) {
        outerHashIn[i] <== outerKeyXOR[i].out;
    }

    
    for (var i = 0; i < 32; i++) {
        outerHashIn[blockSize + i] <== innerHash.out[i];
    }

    component outerHash = Sha256Bytes(blockSize + 32);
    outerHash.in <== outerHashIn;
    hmac <== outerHash.out;
}


template Concat(n1, n2) {
    signal input in1[n1];
    signal input in2[n2];
    signal output out[n1+n2];

    for (var i = 0; i < n1; i++) {
        out[i] <== in1[i];
    }
    for (var i = 0; i < n2; i++) {
        out[n1+i] <== in2[i];
    }
}

template KeyPrep(k) {
    signal input in[k];
    signal output key[64];

    signal blockSize <== 64;

    signal paddingKey[k];
    signal shaKey[64];

    component sha = Sha256Bytes(k);
    for (var i = 0; i < k; i++) {
        sha.in[i] <== in[i];
    }

    component gtChecker = GreaterThan(8);
    gtChecker.in[0] <== k;
    gtChecker.in[1] <== blockSize;

    component selectors[64];
    for (var i = 0; i < 64; i++) {
        selectors[i] = Selector();
        selectors[i].condition <== gtChecker.out;

        if (i < 32) {
            selectors[i].in[0] <== sha.out[i];
        } else {
            selectors[i].in[0] <== 0;
        }

         if (i < k) {
            selectors[i].in[1] <== in[i];
        } else {
            selectors[i].in[1] <== 0;
        }
        key[i] <== selectors[i].out;
    }
}

template Selector() {
    signal input condition;
    signal input in[2];
    signal output out;

    out <== condition * (in[0] - in[1]) + in[1];
}


// XORs two bytes
template XorByte(){
        signal input a;
        signal input b;
        signal output out;

        component abits = Num2Bits(8);
        abits.in <== a;

        component bbits = Num2Bits(8);
        bbits.in <== b;

        component XorBits = XorBits();
        XorBits.a <== abits.out;
        XorBits.b <== bbits.out;

        component num = Bits2Num(8);
        num.in <== XorBits.out;

        out <== num.out;
}

// XORs two arrays of bits
template XorBits(){
        signal input a[8];
        signal input b[8];
        signal output out[8];

    component xor[8];
    for (var i = 0; i < 8; i++) {
        xor[i] = XOR();
        xor[i].a <== a[i];
        xor[i].b <== b[i];
        out[i] <== xor[i].out;
    }
}