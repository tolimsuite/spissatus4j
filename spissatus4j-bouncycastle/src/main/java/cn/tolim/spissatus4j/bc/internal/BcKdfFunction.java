package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.KDF;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Key derivation engine backed by Bouncy Castle.
 *
 * <p>Supports Argon2id (RFC 9106), scrypt (RFC 7914), PBKDF2 (JCA,
 * HMAC-SHA256/512), HKDF (RFC 5869 through the JDK {@link KDF} API, pinned to
 * the configured provider) and raw bcrypt. All password, salt and info
 * buffers created here are zeroised in {@code finally} blocks; derived output
 * belongs to the caller.</p>
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcKdfFunction implements KdfFunction {

    private static final int ARGON2_MIN_SALT_BYTES = 8;
    private static final int ARGON2_DEFAULT_MEMORY_KIB = 65_536;
    private static final int ARGON2_DEFAULT_ITERATIONS = 3;
    private static final int SCRYPT_DEFAULT_N = 32_768;
    private static final int SCRYPT_DEFAULT_R = 8;
    private static final int PBKDF2_DEFAULT_ITERATIONS = 600_000;
    private static final int BCRYPT_SALT_BYTES = 16;
    private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;
    private static final int BCRYPT_DEFAULT_COST = 12;
    private static final int DEFAULT_OUTPUT_BYTES = 32;

    private final AlgorithmId algorithm;
    private final Provider provider;

    public BcKdfFunction(AlgorithmId algorithm, Provider provider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public byte[] derive(byte[] inputKeyMaterial, char[] password, Salt salt, KdfParameters parameters) {
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(parameters, "parameters");
        if (algorithm.equals(AlgorithmId.ARGON2ID)) {
            return deriveArgon2id(password, salt, parameters);
        }
        if (algorithm.equals(AlgorithmId.SCRYPT)) {
            return deriveScrypt(password, salt, parameters);
        }
        if (algorithm.equals(AlgorithmId.PBKDF2)) {
            return derivePbkdf2(password, salt, parameters);
        }
        if (algorithm.equals(AlgorithmId.HKDF)) {
            return deriveHkdf(inputKeyMaterial, salt, parameters);
        }
        if (algorithm.equals(AlgorithmId.BCRYPT)) {
            return deriveBcrypt(password, salt, parameters);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public boolean needsRehash(KdfParameters parameters) {
        Objects.requireNonNull(parameters, "parameters");
        if (algorithm.equals(AlgorithmId.ARGON2ID)) {
            if (!(parameters instanceof KdfParameters.Argon2id p)) {
                throw parameterMismatch();
            }
            return p.memoryKib() < ARGON2_DEFAULT_MEMORY_KIB
                    || p.iterations() < ARGON2_DEFAULT_ITERATIONS
                    || p.outputBytes() < DEFAULT_OUTPUT_BYTES
                    || p.version() < 19;
        }
        if (algorithm.equals(AlgorithmId.SCRYPT)) {
            if (!(parameters instanceof KdfParameters.Scrypt p)) {
                throw parameterMismatch();
            }
            return p.n() < SCRYPT_DEFAULT_N || p.r() < SCRYPT_DEFAULT_R
                    || p.p() < 1 || p.outputBytes() < DEFAULT_OUTPUT_BYTES;
        }
        if (algorithm.equals(AlgorithmId.PBKDF2)) {
            if (!(parameters instanceof KdfParameters.Pbkdf2 p)) {
                throw parameterMismatch();
            }
            return p.iterations() < PBKDF2_DEFAULT_ITERATIONS;
        }
        if (algorithm.equals(AlgorithmId.HKDF)) {
            if (!(parameters instanceof KdfParameters.Hkdf p)) {
                throw parameterMismatch();
            }
            return p.outputBytes() < DEFAULT_OUTPUT_BYTES;
        }
        if (algorithm.equals(AlgorithmId.BCRYPT)) {
            if (!(parameters instanceof KdfParameters.Bcrypt p)) {
                throw parameterMismatch();
            }
            return p.cost() < BCRYPT_DEFAULT_COST;
        }
        throw CryptoException.unsupported(algorithm);
    }

    private byte[] deriveArgon2id(char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Argon2id params)) {
            throw parameterMismatch();
        }
        if (password == null) {
            throw passwordRequired();
        }
        byte[] saltBytes = salt.asBytes();
        if (saltBytes.length < ARGON2_MIN_SALT_BYTES) {
            BcProviders.clear(saltBytes);
            throw BcProviders.invalidParameter("Argon2id requires a salt of at least 8 bytes");
        }
        char[] passwordCopy = password.clone();
        byte[] passwordBytes = null;
        Argon2Parameters argonParameters = null;
        try {
            passwordBytes = encodeUtf8(passwordCopy);
            argonParameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(params.version() == 19
                            ? Argon2Parameters.ARGON2_VERSION_13
                            : Argon2Parameters.ARGON2_VERSION_10)
                    .withMemoryAsKB(params.memoryKib())
                    .withIterations(params.iterations())
                    .withParallelism(params.parallelism())
                    .withSalt(saltBytes)
                    .build();
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(argonParameters);
            byte[] output = new byte[params.outputBytes()];
            generator.generateBytes(passwordBytes, output, 0, output.length);
            return output;
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw BcProviders.invalidParameter("Invalid Argon2id parameters");
        } finally {
            BcProviders.clear(passwordCopy);
            BcProviders.clear(passwordBytes);
            BcProviders.clear(saltBytes);
            if (argonParameters != null) {
                argonParameters.clear();
            }
        }
    }

    private byte[] deriveScrypt(char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Scrypt params)) {
            throw parameterMismatch();
        }
        if (password == null) {
            throw passwordRequired();
        }
        byte[] saltBytes = salt.asBytes();
        if (saltBytes.length == 0) {
            throw BcProviders.invalidParameter("scrypt requires a non-empty salt");
        }
        char[] passwordCopy = password.clone();
        byte[] passwordBytes = null;
        try {
            passwordBytes = encodeUtf8(passwordCopy);
            return SCrypt.generate(passwordBytes, saltBytes, params.n(), params.r(), params.p(),
                    params.outputBytes());
        } catch (IllegalArgumentException e) {
            throw BcProviders.invalidParameter("Invalid scrypt parameters");
        } finally {
            BcProviders.clear(passwordCopy);
            BcProviders.clear(passwordBytes);
            BcProviders.clear(saltBytes);
        }
    }

    private byte[] derivePbkdf2(char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Pbkdf2 params)) {
            throw parameterMismatch();
        }
        if (password == null) {
            throw passwordRequired();
        }
        byte[] saltBytes = salt.asBytes();
        if (saltBytes.length == 0) {
            throw BcProviders.invalidParameter("PBKDF2 requires a non-empty salt");
        }
        char[] passwordCopy = password.clone();
        PBEKeySpec spec = null;
        try {
            String factoryName = "HmacSHA512".equals(params.prf())
                    ? "PBKDF2WithHmacSHA512"
                    : "PBKDF2WithHmacSHA256";
            SecretKeyFactory factory = SecretKeyFactory.getInstance(factoryName, provider);
            spec = new PBEKeySpec(passwordCopy, saltBytes, params.iterations(), params.outputBytes() * 8);
            byte[] derived = factory.generateSecret(spec).getEncoded();
            if (derived.length != params.outputBytes()) {
                BcProviders.clear(derived);
                throw BcProviders.providerFailure("PBKDF2 produced an unexpected key length");
            }
            return derived;
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("PBKDF2 is unavailable");
        } catch (InvalidKeySpecException | IllegalArgumentException e) {
            throw BcProviders.invalidParameter("Invalid PBKDF2 parameters");
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            BcProviders.clear(passwordCopy);
            BcProviders.clear(saltBytes);
        }
    }

    private byte[] deriveHkdf(byte[] inputKeyMaterial, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Hkdf params)) {
            throw parameterMismatch();
        }
        if (inputKeyMaterial == null || inputKeyMaterial.length == 0) {
            throw BcProviders.invalidParameter("HKDF requires input key material");
        }
        boolean sha512 = "HmacSHA512".equals(params.digest());
        int hashLength = sha512 ? 64 : 32;
        int outputBytes = params.outputBytes();
        if (outputBytes < 1 || outputBytes > 255 * hashLength) {
            throw BcProviders.invalidParameter("HKDF output length exceeds the RFC 5869 bound");
        }
        byte[] saltBytes = salt.asBytes();
        byte[] info = params.info();
        byte[] output;
        try {
            // Pinned to the configured provider: a FIPS deployment never falls
            // back to the JDK SunJCE implementation or to a lightweight engine.
            KDF kdf = KDF.getInstance(sha512 ? "HKDF-SHA512" : "HKDF-SHA256", provider);
            HKDFParameterSpec.Builder spec = HKDFParameterSpec.ofExtract()
                    .addIKM(inputKeyMaterial);
            if (saltBytes.length > 0) {
                spec = spec.addSalt(saltBytes);
            }
            output = kdf.deriveData(spec.thenExpand(info, outputBytes));
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("HKDF is unavailable");
        } catch (InvalidAlgorithmParameterException | IllegalArgumentException e) {
            throw BcProviders.invalidParameter("Invalid HKDF parameters");
        } catch (RuntimeException e) {
            throw BcProviders.providerFailure("HKDF derivation failed");
        } finally {
            BcProviders.clear(saltBytes);
            BcProviders.clear(info);
        }
        if (output.length != outputBytes) {
            BcProviders.clear(output);
            throw BcProviders.providerFailure("HKDF produced an unexpected output length");
        }
        return output;
    }

    private byte[] deriveBcrypt(char[] password, Salt salt, KdfParameters parameters) {
        if (!(parameters instanceof KdfParameters.Bcrypt params)) {
            throw parameterMismatch();
        }
        if (password == null) {
            throw passwordRequired();
        }
        byte[] saltBytes = salt.asBytes();
        if (saltBytes.length != BCRYPT_SALT_BYTES) {
            BcProviders.clear(saltBytes);
            throw BcProviders.invalidParameter("bcrypt requires a 16-byte salt");
        }
        char[] passwordCopy = password.clone();
        byte[] passwordBytes = null;
        try {
            passwordBytes = encodeUtf8(passwordCopy);
            if (passwordBytes.length > BCRYPT_MAX_PASSWORD_BYTES) {
                throw BcProviders.invalidParameter("bcrypt passwords must not exceed 72 bytes");
            }
            return BCrypt.generate(passwordBytes, saltBytes, params.cost(), true);
        } catch (IllegalArgumentException e) {
            throw BcProviders.invalidParameter("Invalid bcrypt parameters");
        } finally {
            BcProviders.clear(passwordCopy);
            BcProviders.clear(passwordBytes);
            BcProviders.clear(saltBytes);
        }
    }

    private static byte[] encodeUtf8(char[] password) {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
        ByteBuffer buffer = null;
        try {
            buffer = encoder.encode(CharBuffer.wrap(password));
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return bytes;
        } catch (CharacterCodingException e) {
            throw BcProviders.invalidParameter("Password contains invalid characters");
        } finally {
            if (buffer != null && buffer.hasArray()) {
                Arrays.fill(buffer.array(), (byte) 0);
            }
        }
    }

    private static CryptoException passwordRequired() {
        return BcProviders.invalidParameter("A password is required for this KDF");
    }

    private static CryptoException parameterMismatch() {
        return new CryptoException(ErrorCode.INVALID_PARAMETER,
                "KDF parameters do not match the algorithm");
    }
}