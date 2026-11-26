package cn.tolim.spissatus4j.gm.internal;

import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * RFC 5869 HKDF built on HMAC-SM3. Used to derive per-message Encrypt-then-MAC
 * keys for the SM4 block modes that are not AEAD.
 */
public final class HkdfSm3 {

    public static final int HASH_LENGTH = 32;

    private HkdfSm3() {
    }

    /** RFC 5869 extract step; an empty salt is replaced by HashLen zero bytes. */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(ikm, "ikm");
        Objects.requireNonNull(salt, "salt");
        if (ikm.length == 0) {
            throw new IllegalArgumentException("Input key material must not be empty");
        }
        byte[] effectiveSalt = salt.length == 0 ? new byte[HASH_LENGTH] : salt;
        try {
            HMac mac = new HMac(new SM3Digest());
            mac.init(new KeyParameter(effectiveSalt));
            mac.update(ikm, 0, ikm.length);
            byte[] prk = new byte[HASH_LENGTH];
            mac.doFinal(prk, 0);
            return prk;
        } finally {
            if (salt.length == 0) {
                Arrays.fill(effectiveSalt, (byte) 0);
            }
        }
    }

    /** RFC 5869 expand step. */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        Objects.requireNonNull(prk, "prk");
        Objects.requireNonNull(info, "info");
        if (prk.length != HASH_LENGTH) {
            throw new IllegalArgumentException("HKDF-SM3 PRK must be 32 bytes");
        }
        if (length < 0 || length > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("Invalid HKDF output length");
        }
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        try {
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                HMac mac = new HMac(new SM3Digest());
                mac.init(new KeyParameter(prk));
                mac.update(previous, 0, previous.length);
                mac.update(info, 0, info.length);
                mac.update((byte) counter);
                byte[] block = new byte[HASH_LENGTH];
                mac.doFinal(block, 0);
                Arrays.fill(previous, (byte) 0);
                previous = block;
                int copyLength = Math.min(HASH_LENGTH, length - offset);
                System.arraycopy(block, 0, output, offset, copyLength);
                offset += copyLength;
                counter++;
            }
            return output;
        } finally {
            Arrays.fill(previous, (byte) 0);
        }
    }

    /** Full extract-and-expand derivation; the intermediate PRK is cleared. */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, info, length);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }
}