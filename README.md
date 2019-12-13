# bip32

Created on Fri, 13th, Dec 2019  
Last updated on Fri, 13th, Dec 2019 

## Intro
A deep dive into address derivation, specifically, public key child derivation (KCD).  
As I have found myself lately absorbed by KCD, I wanted to familiarise myself with the ins and outs
of key derivation as described by https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki  
With crypto-currencies, it really feels like I took the wrong pill (the red one) ...  

## Why only Public KCD
Private keys should never leave their secure enclave (like a HSM), and once a wallet address has
been generated, understanding extended public key derivation is critical for wallet management.
This readme is a step-y-step guide for KCD in Java.

## References
I used the following resources:
- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- https://github.com/bitcoinj/bitcoinj
- https://iancoleman.io/bip39/
- and Google of course!

## Extended Key Format
We will start with the format for the extended key. Refer to bip-0032.mediawiki.
See [ExtClass](../code/src/tj/bip32/ExtClass)

```java
    // (4 bytes): version bytes
    private int version; 
    // (33 bytes): the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
    private byte[] keyData; 
    // (32 bytes): chain code
    private byte[] chainCode; 
    // (1 byte): 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    private byte depth; 
    // (4 bytes): child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    private int childNumber; 
    // (4 bytes): the fingerprint of the parent's key (0x00000000 if master key)
    private int fingerPrint; 
    private byte[] checksum;
```