package tj.bip32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public final class CryptoUtils {
    public static byte[] hmacSHA512(final byte[] data, final byte[] seed) throws Exception {
        final Mac hmacSha512 = Mac.getInstance("HmacSHA512");
        final SecretKeySpec keySpec = new SecretKeySpec(data, "HmacSHA512");
        hmacSha512.init(keySpec);
        return hmacSha512.doFinal(seed);
    }

    public static byte[] sha256Twice(final byte[] data, final int offset, final int length) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(data, offset, length);
        digest.update(digest.digest());
        return digest.digest();
    }

    public static byte[] ripemd160(final byte[] data) throws Exception {
        final MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        return ripemd160.digest(data);
    }

    public static byte[] sha256(final byte[] data) throws Exception {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(data);
    }
}
