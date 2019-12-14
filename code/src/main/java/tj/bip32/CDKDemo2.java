package tj.bip32;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class CDKDemo2 {
    public CDKDemo2() throws Exception {
        final String accExtPubKeyB58 = "xpub6CcfWyQsUNdu1w8eTAKiadQPxK45d9TDTehCjNc6xXFksw3G8YSfhPKuUrrZJQrmQMqfEkjREQhvzWRAoJWRPYeSWbTZ7btLzhRJFQdAJGh";
        final ExtKey extPubKey = ExtKey.fromBase58(accExtPubKeyB58);
        System.out.println("Base Acc: " + extPubKey);

        final ExtKey extPubKeyDer0 = extPubKey.derive(0);
        assert "xpub6EzXX3stFnri51K1GrTFCxXvgia7w9ZMchSHZXzGxwUNrtUJuomaobnoNnML1EGTKUBX4T6DRdrRRaAfoBynanEmXX7mmzQa9yEjhTsHdDT".equals(KCDUtils.asBase58(extPubKeyDer0.asByteArray()));
        System.out.println("Derived Acc /0: " +  KCDUtils.asBase58(extPubKeyDer0.asByteArray()));
        System.out.println("Key /0: " + KCDUtils.keyAsHex(extPubKeyDer0.getKeyData()));

        final ExtKey extPubKeyDer00 = extPubKeyDer0.derive(0);
        final String key00 = KCDUtils.keyAsHex(extPubKeyDer00.getKeyData());
        System.out.println("Key /0/0: " + key00);
        System.out.println("P2PKH /0/0: " + KCDUtils.asP2PKH(extPubKeyDer00.getKeyData()));
        assert "030ce8ffe20e1ecc317cf6f0eab9ef3fdc5991c77973ec7313a404010dbfad192f".equals(key00);
        assert "15DVXaQMPEeUtB6inmU7WvxQvN5kASgCZ9".equals(KCDUtils.asP2PKH(extPubKeyDer00.getKeyData()));
    }

    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            new CDKDemo2();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
