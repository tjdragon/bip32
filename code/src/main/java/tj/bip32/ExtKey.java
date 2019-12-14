package tj.bip32;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public final class ExtKey {
    private int version; // (4 bytes): version bytes
    private boolean neutered;
    private byte[] keyData; // (33 bytes): the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
    private byte[] chainCode; // (32 bytes): chain code
    private byte depth; // (1 byte): 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    private int childNumber; // (4 bytes): child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    private int fingerPrint; // (4 bytes): the fingerprint of the parent's key (0x00000000 if master key)
    private byte[] checksum;

    public ExtKey derive(final int index) throws Exception {
        // check for hardened index
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

    public byte[] asByteArray() throws Exception {
        final byte[] data = new byte[82];
        // arraycopy​(Object src, int srcPos, Object dest, int destPos, int length)
        System.arraycopy(KCDUtils.ser32(version), 0, data, 0, 4); // 4 bytes
        data[4] = depth; // 1 byte
        System.arraycopy(KCDUtils.ser32(fingerPrint), 0, data, 5, 4); // 4 bytes
        System.arraycopy(KCDUtils.ser32(childNumber), 0, data, 9, 4); // 4 bytes
        System.arraycopy(chainCode, 0, data, 13, 32); // 32 bytes
        if (!neutered)
            data[45] = (byte) 0;
        System.arraycopy(keyData, 0, data, 45, 33); // 33 bytes
        final byte[] cs = KCDUtils.checksum(data);
        final byte[] cs4 = new byte[4];

        System.arraycopy(cs, 0, data, 78, 4); // 4 bytes

        System.arraycopy(data, 78, cs4, 0, 4); // 4 bytes
        this.checksum = cs4;

        return data;
    }

    public ExtKey version(final int version) {
        this.version = version;
        return this;
    }

    public ExtKey depth(final byte depth) {
        this.depth = depth;
        return this;
    }

    public ExtKey fingerPrint(final int fingerPrint) {
        this.fingerPrint = fingerPrint;
        return this;
    }

    public ExtKey childNumber(final int childNumber) {
        this.childNumber = childNumber;
        return this;
    }

    public ExtKey chainCode(final byte[] chainCode) {
        this.chainCode = chainCode;
        return this;
    }

    public ExtKey keyData(final byte[] keyData) {
        this.keyData = keyData;
        return this;
    }

    public ExtKey neutered(final boolean neutered) {
        this.neutered = neutered;
        return this;
    }

    public byte[] getKeyData() {
        return keyData;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public int getFingerPrint() {
        return fingerPrint;
    }

    @Override
    public String toString() {
        return "ExtKey{" +
                "version=" + version +
                ", neutered=" + neutered +
                ", keyData=" + Arrays.toString(keyData) +
                ", chainCode=" + Arrays.toString(chainCode) +
                ", depth=" + depth +
                ", childNumber=" + childNumber +
                ", fingerPrint=" + fingerPrint +
                ", checksum=" + Arrays.toString(checksum) +
                '}';
    }
}
