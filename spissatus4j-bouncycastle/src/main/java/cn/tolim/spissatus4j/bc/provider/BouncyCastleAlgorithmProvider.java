package cn.tolim.spissatus4j.bc.provider;

import cn.tolim.spissatus4j.bc.algorithm.BcAlgorithmMapper;
import cn.tolim.spissatus4j.bc.internal.BcAeadCipher;
import cn.tolim.spissatus4j.bc.internal.BcAsymmetricCipher;
import cn.tolim.spissatus4j.bc.internal.BcEciesCipher;
import cn.tolim.spissatus4j.bc.internal.BcHashFunction;
import cn.tolim.spissatus4j.bc.internal.BcKdfFunction;
import cn.tolim.spissatus4j.bc.internal.BcMacFunction;
import cn.tolim.spissatus4j.bc.internal.BcProviders;
import cn.tolim.spissatus4j.bc.internal.BcSelfCheck;
import cn.tolim.spissatus4j.bc.internal.BcSignatureFunction;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.security.Provider;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Bouncy Castle backed {@link AlgorithmProvider}.
 *
 * <p>All JCA lookups are pinned to an explicit provider instance, so installing
 * or not installing the {@code BC} provider in the global JCA registry never
 * changes which implementation is selected. FIPS mode exposes only algorithms
 * marked FIPS-approved in the contract catalog and expects the supplied
 * provider to be the Bouncy Castle FIPS provider.</p>
 */
public final class BouncyCastleAlgorithmProvider implements AlgorithmProvider {

    /** Stable provider identifier. */
    public static final String PROVIDER_ID = "bouncycastle";

    /** Provider priority; below the in-house crypto engines. */
    public static final int PRIORITY = 90;

    private static final Set<AlgorithmId> ALL_SUPPORTED = Set.of(
            AlgorithmId.AES_GCM,
            AlgorithmId.CHACHA20_POLY1305,
            AlgorithmId.SHA_256,
            AlgorithmId.SHA_384,
            AlgorithmId.SHA_512,
            AlgorithmId.SHA3_256,
            AlgorithmId.SHA3_512,
            AlgorithmId.SHAKE_128,
            AlgorithmId.SHAKE_256,
            AlgorithmId.BLAKE2B_256,
            AlgorithmId.BLAKE2B_512,
            AlgorithmId.HMAC_SHA256,
            AlgorithmId.HMAC_SHA384,
            AlgorithmId.HMAC_SHA512,
            AlgorithmId.CMAC_AES,
            AlgorithmId.ARGON2ID,
            AlgorithmId.SCRYPT,
            AlgorithmId.PBKDF2,
            AlgorithmId.HKDF,
            AlgorithmId.BCRYPT,
            AlgorithmId.ED448,
            AlgorithmId.RSA_PSS,
            AlgorithmId.RSA_PKCS1_SIGNATURE,
            AlgorithmId.ECDSA_P256,
            AlgorithmId.ECDSA_P384,
            AlgorithmId.RSA_OAEP,
            AlgorithmId.ECIES);

    private static final Set<AlgorithmId> FIPS_SUPPORTED = ALL_SUPPORTED.stream()
            .filter(algorithm -> algorithm.info().fipsApproved())
            .collect(Collectors.toUnmodifiableSet());

    private static final PSSParameterSpec RSA_PSS_SHA256 = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    private final Provider jcaProvider;
    private final BcAlgorithmMapper mapper;
    private final Set<AlgorithmId> supported;
    private final boolean fipsMode;

    /** Creates a provider over the registered (or a fresh) Bouncy Castle provider. */
    public BouncyCastleAlgorithmProvider() {
        this(BcProviders.resolveProvider(), false);
    }

    /** Creates a non-FIPS provider over an explicit JCA provider. */
    public BouncyCastleAlgorithmProvider(Provider jcaProvider) {
        this(jcaProvider, false);
    }

    /**
     * Creates a provider over an explicit JCA provider.
     *
     * @param jcaProvider provider used for every JCA lookup
     * @param fipsMode when true, only FIPS-approved algorithms are exposed
     */
    public BouncyCastleAlgorithmProvider(Provider jcaProvider, boolean fipsMode) {
        this.jcaProvider = Objects.requireNonNull(jcaProvider, "jcaProvider");
        this.mapper = new BcAlgorithmMapper();
        this.supported = fipsMode ? FIPS_SUPPORTED : ALL_SUPPORTED;
        this.fipsMode = fipsMode;
    }

    /** Returns the JCA provider used for every lookup. */
    public Provider jcaProvider() {
        return jcaProvider;
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public int priority() {
        return PRIORITY;
    }

    @Override
    public Set<AlgorithmId> supportedAlgorithms() {
        return supported;
    }

    @Override
    public boolean fipsCapable() {
        return fipsMode;
    }

    @Override
    public AeadCipher aeadCipher(AlgorithmId algorithm) {
        requireSupported(algorithm);
        if (algorithm.equals(AlgorithmId.AES_GCM)) {
            return new BcAeadCipher(algorithm, "AES/GCM/NoPadding", jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.CHACHA20_POLY1305)) {
            return new BcAeadCipher(algorithm, "ChaCha20-Poly1305", jcaProvider);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public AsymmetricCipher asymmetricCipher(AlgorithmId algorithm) {
        requireSupported(algorithm);
        if (algorithm.equals(AlgorithmId.RSA_OAEP)) {
            return new BcAsymmetricCipher(algorithm, jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.ECIES)) {
            return new BcEciesCipher(algorithm, jcaProvider);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public HashFunction hash(AlgorithmId algorithm) {
        requireSupported(algorithm);
        int digestLength = digestLength(algorithm);
        return new BcHashFunction(algorithm, digestLength, mapper.jcaName(algorithm), jcaProvider);
    }

    private static int digestLength(AlgorithmId algorithm) {
        if (algorithm.equals(AlgorithmId.SHA_256) || algorithm.equals(AlgorithmId.SHA3_256)
                || algorithm.equals(AlgorithmId.SHAKE_128)
                || algorithm.equals(AlgorithmId.BLAKE2B_256)) {
            return 32;
        }
        if (algorithm.equals(AlgorithmId.SHA_384)) {
            return 48;
        }
        if (algorithm.equals(AlgorithmId.SHA_512) || algorithm.equals(AlgorithmId.SHA3_512)
                || algorithm.equals(AlgorithmId.SHAKE_256)
                || algorithm.equals(AlgorithmId.BLAKE2B_512)) {
            return 64;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public MacFunction mac(AlgorithmId algorithm) {
        requireSupported(algorithm);
        if (algorithm.equals(AlgorithmId.HMAC_SHA256)) {
            return new BcMacFunction(algorithm, 32, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.HMAC_SHA384)) {
            return new BcMacFunction(algorithm, 48, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.HMAC_SHA512)) {
            return new BcMacFunction(algorithm, 64, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.CMAC_AES)) {
            return new BcMacFunction(algorithm, 16, mapper.jcaName(algorithm), jcaProvider);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SignatureFunction signature(AlgorithmId algorithm) {
        requireSupported(algorithm);
        if (algorithm.equals(AlgorithmId.ED448)) {
            return new BcSignatureFunction(algorithm, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.RSA_PSS)) {
            return new BcSignatureFunction(algorithm, mapper.jcaName(algorithm), jcaProvider,
                    RSA_PSS_SHA256);
        }
        if (algorithm.equals(AlgorithmId.RSA_PKCS1_SIGNATURE)) {
            return new BcSignatureFunction(algorithm, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.ECDSA_P256)) {
            return new BcSignatureFunction(algorithm, mapper.jcaName(algorithm), jcaProvider);
        }
        if (algorithm.equals(AlgorithmId.ECDSA_P384)) {
            return new BcSignatureFunction(algorithm, mapper.jcaName(algorithm), jcaProvider);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public KdfFunction kdf(AlgorithmId algorithm) {
        requireSupported(algorithm);
        if (algorithm.equals(AlgorithmId.ARGON2ID) || algorithm.equals(AlgorithmId.SCRYPT)
                || algorithm.equals(AlgorithmId.PBKDF2) || algorithm.equals(AlgorithmId.HKDF)
                || algorithm.equals(AlgorithmId.BCRYPT)) {
            return new BcKdfFunction(algorithm, jcaProvider);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SelfCheckReport selfCheck() {
        return BcSelfCheck.run(this, jcaProvider);
    }

    @Override
    public void close() {
        // Stateless engine factory; the JCA provider is owned by the caller.
    }

    private void requireSupported(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (!supported.contains(algorithm)) {
            throw CryptoException.unsupported(algorithm);
        }
    }
}