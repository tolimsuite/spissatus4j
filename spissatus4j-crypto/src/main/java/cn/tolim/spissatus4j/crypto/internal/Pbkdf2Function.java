package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC password derivation.
 *
 * <p>The provider output must have exactly the requested length; a provider
 * that returns a short or over-long encoding is treated as a failure rather
 * than padded or truncated.</p>
 */
final class Pbkdf2Function implements KdfFunction {

    static final int DEFAULT_ITERATIONS = 600_000;

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.PBKDF2;
    }

    @Override
    public byte[] derive(byte[] inputKeyMaterial, char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Pbkdf2 pbkdf2)) {
            throw new IllegalArgumentException("PBKDF2 requires Pbkdf2 parameters");
        }
        if (inputKeyMaterial != null) {
            throw new IllegalArgumentException("PBKDF2 does not accept input key material");
        }
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(salt, "salt");
        if (password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        char[] passwordCopy = password.clone();
        byte[] saltBytes = salt.asBytes();
        try {
            String jcaName = "HmacSHA512".equals(pbkdf2.prf())
                    ? "PBKDF2WithHmacSHA512" : "PBKDF2WithHmacSHA256";
            SecretKeyFactory factory = SecretKeyFactory.getInstance(jcaName);
            return deriveWith(factory, passwordCopy, saltBytes, pbkdf2.iterations(),
                    pbkdf2.outputBytes());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "PBKDF2 derivation failed", e);
        } finally {
            Arrays.fill(passwordCopy, '\0');
            CryptoSupport.wipe(saltBytes);
        }
    }

    /**
     * Runs one derivation through the supplied factory. Package-private so a
     * test can inject a factory that returns a wrong-length key; production
     * callers always pass the JCA factory selected by the PRF.
     */
    static byte[] deriveWith(SecretKeyFactory factory, char[] password, byte[] salt,
                             int iterations, int outputBytes) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, outputBytes * 8);
        try {
            SecretKey derived = factory.generateSecret(spec);
            return requireDerivedLength(derived.getEncoded(), outputBytes);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Enforces an exact provider output length. Padding or truncating a
     * mismatched encoding would silently change the derived key, so the bytes
     * are wiped and a generic provider failure is raised instead.
     */
    static byte[] requireDerivedLength(byte[] encoded, int expectedLength) {
        if (encoded == null || encoded.length != expectedLength) {
            CryptoSupport.wipe(encoded);
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "PBKDF2 provider returned an unexpected derived key length");
        }
        return encoded;
    }

    @Override
    public boolean needsRehash(KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Pbkdf2 pbkdf2)) {
            throw new IllegalArgumentException("PBKDF2 requires Pbkdf2 parameters");
        }
        return pbkdf2.iterations() < DEFAULT_ITERATIONS;
    }
}
