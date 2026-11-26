package cn.tolim.spissatus4j.bc.algorithm;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bidirectional mapping between stable {@link AlgorithmId}s and the JCA names
 * implemented by the Bouncy Castle provider.
 *
 * <p>The mapping is injective: registering a second, different name for an
 * algorithm, or a second, different algorithm for a JCA name, is rejected with
 * a {@link ConfigurationException}. Looking up a missing mapping throws a
 * {@link CryptoException} with {@link ErrorCode#ALGORITHM_UNSUPPORTED}; the
 * mapper never falls back to a default JCA transformation.</p>
 */
public final class BcAlgorithmMapper {

    private final Map<AlgorithmId, String> byAlgorithm = new LinkedHashMap<>();
    private final Map<String, AlgorithmId> byJcaName = new LinkedHashMap<>();

    /** Creates a mapper pre-populated with the Bouncy Castle standard mappings. */
    public BcAlgorithmMapper() {
        registerStandardMappings();
    }

    /** Returns a mapper with the standard mappings. */
    public static BcAlgorithmMapper standard() {
        return new BcAlgorithmMapper();
    }

    /**
     * Registers a mapping. Re-registering the same pair is a no-op; conflicting
     * mappings are rejected.
     */
    public synchronized void register(AlgorithmId algorithm, String jcaName) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(jcaName, "jcaName");
        String name = jcaName.trim();
        if (name.isEmpty()) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "JCA name must not be empty");
        }
        String existingName = byAlgorithm.get(algorithm);
        if (existingName != null && !existingName.equals(name)) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Conflicting JCA mapping for " + algorithm.id());
        }
        AlgorithmId existingAlgorithm = byJcaName.get(normalize(name));
        if (existingAlgorithm != null && !existingAlgorithm.equals(algorithm)) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Conflicting algorithm mapping for a JCA name");
        }
        byAlgorithm.put(algorithm, name);
        byJcaName.put(normalize(name), algorithm);
    }

    /**
     * Returns the JCA name for an algorithm.
     *
     * @throws CryptoException when no mapping exists (never a silent fallback)
     */
    public synchronized String jcaName(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        String name = byAlgorithm.get(algorithm);
        if (name == null) {
            throw CryptoException.unsupported(algorithm);
        }
        return name;
    }

    /**
     * Returns the algorithm for a JCA name (case-insensitive).
     *
     * @throws CryptoException when no mapping exists
     */
    public synchronized AlgorithmId algorithm(String jcaName) {
        Objects.requireNonNull(jcaName, "jcaName");
        AlgorithmId algorithm = byJcaName.get(normalize(jcaName));
        if (algorithm == null) {
            throw new CryptoException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "No algorithm is mapped to the given JCA name");
        }
        return algorithm;
    }

    /** Returns whether the algorithm has a mapping. */
    public synchronized boolean hasMapping(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        return byAlgorithm.containsKey(algorithm);
    }

    /** Returns an immutable snapshot of the mapped algorithms. */
    public synchronized Set<AlgorithmId> algorithms() {
        return Set.copyOf(byAlgorithm.keySet());
    }

    private void registerStandardMappings() {
        register(AlgorithmId.AES_GCM, "AES/GCM/NoPadding");
        register(AlgorithmId.CHACHA20_POLY1305, "ChaCha20-Poly1305");

        register(AlgorithmId.SHA_256, "SHA-256");
        register(AlgorithmId.SHA_384, "SHA-384");
        register(AlgorithmId.SHA_512, "SHA-512");
        register(AlgorithmId.SHA3_256, "SHA3-256");
        register(AlgorithmId.SHA3_512, "SHA3-512");
        register(AlgorithmId.SHAKE_128, "SHAKE128-256");
        register(AlgorithmId.SHAKE_256, "SHAKE256-512");
        register(AlgorithmId.BLAKE2B_256, "BLAKE2B-256");
        register(AlgorithmId.BLAKE2B_512, "BLAKE2B-512");

        register(AlgorithmId.HMAC_SHA256, "HmacSHA256");
        register(AlgorithmId.HMAC_SHA384, "HmacSHA384");
        register(AlgorithmId.HMAC_SHA512, "HmacSHA512");
        register(AlgorithmId.CMAC_AES, "AESCMAC");

        register(AlgorithmId.ED448, "Ed448");
        register(AlgorithmId.RSA_PSS, "RSASSA-PSS");
        register(AlgorithmId.RSA_PKCS1_SIGNATURE, "SHA256withRSA");
        register(AlgorithmId.ECDSA_P256, "SHA256withECDSAinP1363Format");
        register(AlgorithmId.ECDSA_P384, "SHA384withECDSAinP1363Format");
        register(AlgorithmId.RSA_OAEP, "RSA/ECB/OAEPPadding");
        register(AlgorithmId.ECIES, "ECIES");

        register(AlgorithmId.ARGON2ID, "Argon2id");
        register(AlgorithmId.SCRYPT, "scrypt");
        register(AlgorithmId.PBKDF2, "PBKDF2WithHmacSHA256");
        register(AlgorithmId.HKDF, "HKDF");
        register(AlgorithmId.BCRYPT, "bcrypt");
    }

    private static String normalize(String jcaName) {
        return jcaName.trim().toUpperCase(Locale.ROOT);
    }
}