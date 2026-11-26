package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 5869 HKDF built on the JCA HMAC implementation. */
final class HkdfFunction implements KdfFunction {

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.HKDF;
    }

    @Override
    public byte[] derive(byte[] inputKeyMaterial, char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Hkdf hkdf)) {
            throw new IllegalArgumentException("HKDF requires Hkdf parameters");
        }
        if (password != null) {
            throw new IllegalArgumentException("HKDF does not accept a password");
        }
        Objects.requireNonNull(inputKeyMaterial, "inputKeyMaterial");
        Objects.requireNonNull(salt, "salt");
        if (inputKeyMaterial.length == 0) {
            throw new IllegalArgumentException("HKDF input key material must not be empty");
        }
        byte[] saltBytes = salt.asBytes();
        try {
            return derive(inputKeyMaterial, saltBytes, hkdf.info(), hkdf.outputBytes(), hkdf.digest());
        } finally {
            CryptoSupport.wipe(saltBytes);
        }
    }

    /**
     * RFC 5869 extract-then-expand.
     *
     * @param inputKeyMaterial input key material
     * @param salt optional salt; empty or {@code null} means a zero salt
     * @param info optional context/application specific information
     * @param length output length in bytes
     * @param macAlgorithm JCA HMAC name, {@code HmacSHA256} or {@code HmacSHA512}
     * @return derived key material
     */
    static byte[] derive(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length,
                         String macAlgorithm) {
        int hashLength = switch (macAlgorithm) {
            case "HmacSHA256" -> 32;
            case "HmacSHA512" -> 64;
            default -> throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported HKDF digest: " + macAlgorithm);
        };
        if (length < 0 || length > 255 * hashLength) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Invalid HKDF output length");
        }
        byte[] effectiveSalt = salt;
        boolean generatedSalt = false;
        if (effectiveSalt == null || effectiveSalt.length == 0) {
            effectiveSalt = new byte[hashLength];
            generatedSalt = true;
        }
        byte[] prk = null;
        byte[] previous = new byte[0];
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(effectiveSalt, macAlgorithm));
            prk = mac.doFinal(inputKeyMaterial);
            byte[] output = new byte[length];
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                mac.init(new SecretKeySpec(prk, macAlgorithm));
                mac.update(previous);
                if (info != null && info.length > 0) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                byte[] block = mac.doFinal();
                int copy = Math.min(block.length, length - offset);
                System.arraycopy(block, 0, output, offset, copy);
                offset += copy;
                CryptoSupport.wipe(previous);
                previous = block;
                counter++;
            }
            return output;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "HKDF derivation failed", e);
        } finally {
            CryptoSupport.wipe(prk);
            CryptoSupport.wipe(previous);
            if (generatedSalt) {
                CryptoSupport.wipe(effectiveSalt);
            }
        }
    }

    @Override
    public boolean needsRehash(KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Hkdf)) {
            throw new IllegalArgumentException("HKDF requires Hkdf parameters");
        }
        return false;
    }
}
