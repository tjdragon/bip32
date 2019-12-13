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