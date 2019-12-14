package tj.bip32;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class KCDUtils {
    public static final int MAIN_NET_PUBLIC = 0x0488B21E;
    public static final int MAIN_NET_PRIVATE = 0x0488ADE4;

    public static byte[] tail32(final byte[] bytes64) {
        final byte[] tail = new byte[bytes64.length - 32];
        System.arraycopy(bytes64, 32, tail, 0, tail.length);
        return tail;
    }

    public static byte[] head32(final byte[] bytes64) {
        return Arrays.copyOf(bytes64, 32);
    }

    public static BigInteger parse256(final byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static int calculateFingerprint(final byte[] key, final boolean neutered) throws Exception {
        final byte[] point = neutered ? key : ECUtils.getPoint(key);
        final byte[] fp = CryptoUtils.ripemd160(CryptoUtils.sha256(point));
        return ByteBuffer.wrap(fp).getInt();
    }

    public static byte[] ser32(final int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }

    public static int deSer32(final byte[] data) {
        return ByteBuffer.wrap(data).getInt();
    }

    public static byte[] checksum(final byte[] keyData) throws Exception {
        return CryptoUtils.sha256Twice(keyData, 0, 78);
    }

    public static String asBase58(final byte[] data) throws Exception {
        return Base58.encode(data);
    }

    public static String keyAsHex(final byte[] data) {
        return Hex.encodeHexString(data);
    }

    public static String asP2PKH(final byte[] keyData) throws Exception {
        final byte[] sha256 = CryptoUtils.sha256(keyData);
        final byte[] ripemd160 = CryptoUtils.ripemd160(sha256);

        final byte[] adr1 = new byte[ripemd160.length + 1];
        System.arraycopy(ripemd160, 0, adr1, 1, ripemd160.length);
        final byte[] checksum = CryptoUtils.sha256(CryptoUtils.sha256(adr1));
        final byte[] cs = new byte[4];
        System.arraycopy(checksum, 0, cs, 0, 4);

        final byte[] adr2 = new byte[adr1.length + 4];
        System.arraycopy(adr1, 0, adr2, 0, adr1.length);
        System.arraycopy(cs, 0, adr2, adr1.length, 4);

        return Base58.encode(adr2);
    }
}
