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
See [ExtKey.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/ExtKey.java)

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

Next a bunch of utility classes, for Elliptic Curves and basic crypto like hashing.

## Elliptic Curve Utils
This class [ECUtils.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/ECUtils.java) contains
the EC utils necessary for key derivation. I am currently using [Bouncy Castle](https://www.bouncycastle.org/) but
when I have time, I will implement the same using the libs from [OpenJDK](https://openjdk.java.net/).  
We are using the secp256k1 curve as shown by the line below:

```java
public static final X9ECParameters secp256k1 = CustomNamedCurves.getByName("secp256k1");
```

## Crypto Utils
Next is [CryptoUtils.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/CryptoUtils.java).
This class contains all the hashing functions required like HMAC SHA 256, RIPEMD160, SHA 256

## KCD Utils
Lastly, [KCDUtils.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/KCDUtils.java).
This class is all about array manipulation and extraction.  

We can now get to the interesting stuff, how to piece all of those utility classes together to create
public KCD and check if it works.

## CDK Demo One
[CDKDemo1.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/CDKDemo1.java) implements CDK
by first creating an extended private key for BTC, then derive its extended public key, 
and finally derive a second extended public key from the first extended public key.

The method derive in [ExtKey.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/ExtKey.java) is where the derivation logic takes place:

```java
    public ExtKey derive(final int index) throws Exception {
        // todo check for hardened index
        final byte[] data = new byte[37];

        System.arraycopy(keyData, 0, data, 0, 33);
        System.arraycopy(KCDUtils.ser32(index), 0, data, 33, 4);

        final byte[] hmacSHA512 = CryptoUtils.hmacSHA512(chainCode, data);
        final byte[] key = KCDUtils.head32(hmacSHA512);
        final byte[] chainCode = KCDUtils.tail32(hmacSHA512);

        final BigInteger keyBigInt = KCDUtils.parse256(key);
        final ECPoint keyECPoint = ECUtils.multiplyAndAdd(keyBigInt, keyData);

        if (keyECPoint.isInfinity() || keyBigInt.compareTo(ECUtils.getN()) >= 0) {
            return derive(index + 1);
        }

        final byte[] keyECData = keyECPoint.getEncoded(true);

        final ExtKey derivedExtKey = new ExtKey()
                .neutered(true)
                .version(version)
                .depth((byte) ((int) depth + 1))
                .fingerPrint(KCDUtils.calculateFingerprint(keyData, neutered))
                .childNumber(index)
                .chainCode(chainCode)
                .keyData(keyECData);

        return derivedExtKey;
    }
```

I used a specific seed which I kew the derived public keys so that I could check the code.

## CDK Demo Two
For this [CDKDemo2.java](https://github.com/tjdragon/bip32/blob/master/code/src/main/java/tj/bip32/CDKDemo2.java)
I went for a reverse logic: using an extended public key from [https://iancoleman.io/bip39/](https://iancoleman.io/bip39/),
I create an instance of ExtKey, I derive the key twice and check the P2PKH address to match what the web site gives.