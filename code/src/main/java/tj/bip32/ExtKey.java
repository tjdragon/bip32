package tj.bip32;

public final class ExtKey {
    private int version; // (4 bytes): version bytes
    private boolean neutered;
    private byte[] keyData; // (33 bytes): the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
    private byte[] chainCode; // (32 bytes): chain code
    private byte depth; // (1 byte): 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    private int childNumber; // (4 bytes): child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    private int fingerPrint; // (4 bytes): the fingerprint of the parent's key (0x00000000 if master key)
    private byte[] checksum;
}
