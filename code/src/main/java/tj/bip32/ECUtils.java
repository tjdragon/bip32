package tj.bip32;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public final class ECUtils {
    public static final X9ECParameters secp256k1 = CustomNamedCurves.getByName("secp256k1");

    public static byte[] getPoint(final byte[] key) {
        final BigInteger bigInteger = new BigInteger(1, key);
        final ECPoint ecPoint = secp256k1.getG().multiply(bigInteger);
        return ecPoint.getEncoded(true);
    }

    public static BigInteger getN() {
        return secp256k1.getN();
    }

    public static ECPoint decode(final byte[] toAdd) {
        return secp256k1.getCurve().decodePoint(toAdd);
    }

    public static ECPoint multiplyAndAdd(final BigInteger bigInteger, final byte[] toAdd) {
        return secp256k1.getG().multiply(bigInteger).add(decode(toAdd));
    }
}
