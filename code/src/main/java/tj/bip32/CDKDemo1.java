package tj.bip32;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

import static tj.bip32.KCDUtils.MAIN_NET_PRIVATE;
import static tj.bip32.KCDUtils.MAIN_NET_PUBLIC;

public class CDKDemo1 {
    public CDKDemo1() throws Exception {
        final String btcSeed = "Bitcoin seed";
        final byte[] btcSeedAsArray = btcSeed.getBytes();

        final String seed = "000102030405060708090a0b0c0d0e0f";
        final byte[] seedAsArray = new byte[0];

        // Create the top extended public key from which we will derive the rest
        final byte[] hmacSHA512 = CryptoUtils.hmacSHA512(btcSeedAsArray, seedAsArray); // 64 bytes
        final byte[] key = KCDUtils.head32(hmacSHA512);
        final byte[] chaincode = KCDUtils.tail32(hmacSHA512);

        final ExtKey extPriKey =
                new ExtKey()
                        .neutered(false)
                        .version(MAIN_NET_PRIVATE)
                        .depth((byte) 0)
                        .fingerPrint(0)
                        .childNumber(0)
                        .chainCode(chaincode)
                        .keyData(key);

        final ExtKey extPubKey =
                new ExtKey()
                        .neutered(true)
                        .version(MAIN_NET_PUBLIC)
                        .depth((byte) 0)
                        .fingerPrint(extPriKey.getFingerPrint())
                        .childNumber(0)
                        .chainCode(extPriKey.getChainCode())
                        .keyData(ECUtils.getPoint(extPriKey.getKeyData()));

        final String pubKeyB58 = KCDUtils.asBase58(extPubKey.asByteArray());
        final boolean eq1 = pubKeyB58.equals("xpub661MyMwAqRbcH2Z5RtM6ydu98YudxiUDTaBESx9VgXpURBCDdWGezitJ8ormADG6CsJPs23fLmaeLp8RJgNvFo6YJkGhpXnHusCkRhGZdqr");
        System.out.println(extPubKey);
        System.out.println(eq1 + " : " + pubKeyB58);

        final ExtKey extPubKeyDerived1 = extPubKey.derive(1);
        final String extPubKeyDerived1B58 = KCDUtils.asBase58(extPubKeyDerived1.asByteArray());
        final boolean eq2 = extPubKeyDerived1B58.equals("xpub68eho38Mba9E3UC1csDPhYiFXQDAMVoxohnZe5v3jDgAHT1hvq4f4WG19SnPC4GnJW5BKCPmtRLG6P7fuHLCgQqz9yqvhiVFhvSkzs1byrP");
        System.out.println(eq2 + " : " + extPubKeyDerived1B58);
    }

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());
            new CDKDemo1();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
