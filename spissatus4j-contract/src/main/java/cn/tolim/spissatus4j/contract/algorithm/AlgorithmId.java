package cn.tolim.spissatus4j.contract.algorithm;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Stable identifier of a cryptographic algorithm (not necessarily a JCA
 * transformation name). Identifiers are intentionally open-ended so that
 * trusted extension providers may register additional algorithms; unknown
 * identifiers carry an {@link SecurityStatus#UNKNOWN} info record and are
 * denied by the default policy.
 */
public final class AlgorithmId implements Comparable<AlgorithmId> {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._/-]{0,63}");

    // ---- symmetric / AEAD ----
    public static final AlgorithmId AES_GCM = new AlgorithmId("AES-GCM");
    public static final AlgorithmId AES_CBC = new AlgorithmId("AES-CBC");
    public static final AlgorithmId AES_CTR = new AlgorithmId("AES-CTR");
    public static final AlgorithmId AES_CFB = new AlgorithmId("AES-CFB");
    public static final AlgorithmId AES_OFB = new AlgorithmId("AES-OFB");
    public static final AlgorithmId AES_KW = new AlgorithmId("AES-KW");
    public static final AlgorithmId AES_ECB = new AlgorithmId("AES-ECB");
    public static final AlgorithmId CHACHA20_POLY1305 = new AlgorithmId("CHACHA20-POLY1305");
    public static final AlgorithmId SM4_GCM = new AlgorithmId("SM4-GCM");
    public static final AlgorithmId SM4_CBC = new AlgorithmId("SM4-CBC");
    public static final AlgorithmId SM4_CTR = new AlgorithmId("SM4-CTR");
    public static final AlgorithmId SM4_ECB = new AlgorithmId("SM4-ECB");
    public static final AlgorithmId SM4 = new AlgorithmId("SM4");
    public static final AlgorithmId DES_CBC = new AlgorithmId("DES-CBC");
    public static final AlgorithmId DES_EDE3_CBC = new AlgorithmId("3DES-CBC");
    public static final AlgorithmId RC4 = new AlgorithmId("RC4");

    // ---- asymmetric encryption / KEM ----
    public static final AlgorithmId RSA_OAEP = new AlgorithmId("RSA-OAEP");
    public static final AlgorithmId RSA_PKCS1 = new AlgorithmId("RSA-PKCS1-V1.5");
    public static final AlgorithmId ECIES = new AlgorithmId("ECIES");
    public static final AlgorithmId SM2 = new AlgorithmId("SM2");
    public static final AlgorithmId ML_KEM_768 = new AlgorithmId("ML-KEM-768");

    // ---- hash ----
    public static final AlgorithmId SHA_256 = new AlgorithmId("SHA-256");
    public static final AlgorithmId SHA_384 = new AlgorithmId("SHA-384");
    public static final AlgorithmId SHA_512 = new AlgorithmId("SHA-512");
    public static final AlgorithmId SHA3_256 = new AlgorithmId("SHA3-256");
    public static final AlgorithmId SHA3_512 = new AlgorithmId("SHA3-512");
    public static final AlgorithmId SHAKE_128 = new AlgorithmId("SHAKE128");
    public static final AlgorithmId SHAKE_256 = new AlgorithmId("SHAKE256");
    public static final AlgorithmId BLAKE2B_256 = new AlgorithmId("BLAKE2B-256");
    public static final AlgorithmId BLAKE2B_512 = new AlgorithmId("BLAKE2B-512");
    public static final AlgorithmId BLAKE3_256 = new AlgorithmId("BLAKE3-256");
    public static final AlgorithmId SM3 = new AlgorithmId("SM3");
    public static final AlgorithmId MD5 = new AlgorithmId("MD5");
    public static final AlgorithmId SHA_1 = new AlgorithmId("SHA-1");

    // ---- MAC ----
    public static final AlgorithmId HMAC_SHA256 = new AlgorithmId("HMAC-SHA256");
    public static final AlgorithmId HMAC_SHA384 = new AlgorithmId("HMAC-SHA384");
    public static final AlgorithmId HMAC_SHA512 = new AlgorithmId("HMAC-SHA512");
    public static final AlgorithmId HMAC_SM3 = new AlgorithmId("HMAC-SM3");
    public static final AlgorithmId CMAC_AES = new AlgorithmId("CMAC-AES");

    // ---- signature ----
    public static final AlgorithmId ED25519 = new AlgorithmId("ED25519");
    public static final AlgorithmId ED448 = new AlgorithmId("ED448");
    public static final AlgorithmId ECDSA_P256 = new AlgorithmId("ECDSA-P256");
    public static final AlgorithmId ECDSA_P384 = new AlgorithmId("ECDSA-P384");
    public static final AlgorithmId RSA_PSS = new AlgorithmId("RSA-PSS");
    public static final AlgorithmId RSA_PKCS1_SIGNATURE = new AlgorithmId("RSA-PKCS1-V1.5-SIGNATURE");
    public static final AlgorithmId DSA = new AlgorithmId("DSA");
    public static final AlgorithmId SM2_SIGNATURE = new AlgorithmId("SM2-SIGNATURE");
    public static final AlgorithmId ML_DSA_65 = new AlgorithmId("ML-DSA-65");

    // ---- KDF ----
    public static final AlgorithmId ARGON2ID = new AlgorithmId("ARGON2ID");
    public static final AlgorithmId SCRYPT = new AlgorithmId("SCRYPT");
    public static final AlgorithmId BCRYPT = new AlgorithmId("BCRYPT");
    public static final AlgorithmId PBKDF2 = new AlgorithmId("PBKDF2");
    public static final AlgorithmId HKDF = new AlgorithmId("HKDF");

    private final String id;
    private final String normalized;

    private AlgorithmId(String id) {
        String candidate = Objects.requireNonNull(id, "id").trim();
        if (!VALID.matcher(candidate).matches()) {
            throw new IllegalArgumentException("Invalid algorithm identifier");
        }
        this.id = candidate;
        this.normalized = candidate.toUpperCase(Locale.ROOT);
    }

    /** Returns the canonical catalog instance when the identifier is known. */
    public static AlgorithmId of(String id) {
        AlgorithmInfo info = AlgorithmCatalog.lookup(id).orElse(null);
        return info == null ? new AlgorithmId(id) : info.id();
    }

    public String id() {
        return id;
    }

    public AlgorithmInfo info() {
        return AlgorithmCatalog.infoOrUnknown(id);
    }

    public AlgorithmFamily family() {
        return info().family();
    }

    public SecurityStatus status() {
        return info().status();
    }

    public boolean isKnown() {
        return AlgorithmCatalog.lookup(id).isPresent();
    }

    @Override
    public int compareTo(AlgorithmId other) {
        return id.compareTo(other.id);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AlgorithmId that && normalized.equals(that.normalized);
    }

    @Override
    public int hashCode() {
        return normalized.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }
}