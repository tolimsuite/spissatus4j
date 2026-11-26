package cn.tolim.spissatus4j.contract.algorithm;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DERIVE;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.MAC;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.SIGN;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.UNWRAP;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.VERIFY;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.WRAP;

/**
 * Static catalog of known algorithms and their security metadata.
 *
 * <p>Third-party providers may register additional trusted entries through
 * {@link #registerExternal(AlgorithmInfo)}. Duplicate identifiers with
 * conflicting metadata are rejected.</p>
 */
public final class AlgorithmCatalog {

    private static final Set<KeyUsage> ENC_DEC = Set.of(ENCRYPT, DECRYPT);
    private static final Set<KeyUsage> WRAP_UNWRAP = Set.of(WRAP, UNWRAP);
    private static final Set<KeyUsage> ENC_DEC_WRAP = Set.of(ENCRYPT, DECRYPT, WRAP, UNWRAP);
    private static final Set<KeyUsage> SIGN_VERIFY = Set.of(SIGN, VERIFY);
    private static final Set<KeyUsage> MAC_ONLY = Set.of(MAC);
    private static final Set<KeyUsage> DERIVE_ONLY = Set.of(DERIVE);

    private static final Map<String, AlgorithmInfo> CATALOG = new LinkedHashMap<>();

    static {
        // Symmetric / AEAD
        add(AlgorithmId.AES_GCM, "AES-GCM", AlgorithmFamily.AEAD, SecurityStatus.RECOMMENDED, 128, 12, 16,
                ENC_DEC, true, false, false, "Default AEAD choice; 96-bit nonces; 128-bit tag");
        add(AlgorithmId.CHACHA20_POLY1305, "ChaCha20-Poly1305", AlgorithmFamily.AEAD,
                SecurityStatus.RECOMMENDED, 256, 12, 16, ENC_DEC, false, false, false,
                "RFC 8439 AEAD; use when AES hardware acceleration is unavailable");
        add(AlgorithmId.AES_CBC, "AES-CBC (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, true, false, false,
                "Never used raw; always wrapped with Encrypt-then-MAC in this library");
        add(AlgorithmId.AES_CTR, "AES-CTR (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, true, false, false,
                "Never used raw; always wrapped with Encrypt-then-MAC in this library");
        add(AlgorithmId.AES_CFB, "AES-CFB (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, true, false, false,
                "Legacy compatibility only; Encrypt-then-MAC enforced");
        add(AlgorithmId.AES_OFB, "AES-OFB (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, true, false, false,
                "Legacy compatibility only; Encrypt-then-MAC enforced");
        add(AlgorithmId.AES_KW, "AES Key Wrap", AlgorithmFamily.SYMMETRIC, SecurityStatus.ACCEPTABLE,
                128, 0, 0, WRAP_UNWRAP, true, false, false, "RFC 3394 key wrapping");
        add(AlgorithmId.AES_ECB, "AES-ECB", AlgorithmFamily.SYMMETRIC, SecurityStatus.PROHIBITED,
                128, 0, 0, ENC_DEC, true, false, false, "ECB leaks plaintext structure and is always denied");
        add(AlgorithmId.SM4_GCM, "SM4-GCM", AlgorithmFamily.AEAD, SecurityStatus.RECOMMENDED,
                128, 12, 16, ENC_DEC, false, true, false, "GM/T 0002 SM4 in GCM mode");
        add(AlgorithmId.SM4_CBC, "SM4-CBC (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, false, true, false,
                "GM/T 0002 SM4; Encrypt-then-MAC enforced");
        add(AlgorithmId.SM4_CTR, "SM4-CTR (Encrypt-then-MAC)", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.ACCEPTABLE, 128, 16, 32, ENC_DEC, false, true, false,
                "GM/T 0002 SM4; Encrypt-then-MAC enforced");
        add(AlgorithmId.SM4_ECB, "SM4-ECB", AlgorithmFamily.SYMMETRIC, SecurityStatus.PROHIBITED,
                128, 0, 0, ENC_DEC, false, true, false, "ECB is always denied");
        add(AlgorithmId.SM4, "SM4 raw block cipher", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.PROHIBITED, 128, 0, 0, ENC_DEC, false, true, false,
                "Raw block cipher use is not exposed; use SM4-GCM/CBC/CTR");
        add(AlgorithmId.DES_CBC, "DES-CBC", AlgorithmFamily.SYMMETRIC, SecurityStatus.PROHIBITED,
                56, 8, 0, ENC_DEC, false, false, false, "Broken cipher; always denied");
        add(AlgorithmId.DES_EDE3_CBC, "3DES-CBC", AlgorithmFamily.SYMMETRIC,
                SecurityStatus.DEPRECATED, 168, 8, 32, ENC_DEC, false, false, false,
                "Legacy compatibility only; deprecated and warned");
        add(AlgorithmId.RC4, "RC4", AlgorithmFamily.SYMMETRIC, SecurityStatus.PROHIBITED,
                0, 0, 0, ENC_DEC, false, false, false, "Broken cipher; always denied");

        // Asymmetric encryption / KEM
        add(AlgorithmId.RSA_OAEP, "RSA-OAEP", AlgorithmFamily.ASYMMETRIC, SecurityStatus.RECOMMENDED,
                2048, 0, 0, ENC_DEC_WRAP, true, false, false, "OAEP with SHA-256 and MGF1-SHA-256");
        add(AlgorithmId.RSA_PKCS1, "RSA PKCS#1 v1.5 encryption", AlgorithmFamily.ASYMMETRIC,
                SecurityStatus.DEPRECATED, 2048, 0, 0, ENC_DEC, true, false, false,
                "Legacy interoperability only; vulnerable to padding oracles");
        add(AlgorithmId.ECIES, "ECIES", AlgorithmFamily.ASYMMETRIC, SecurityStatus.ACCEPTABLE,
                256, 0, 0, ENC_DEC, false, false, false,
                "EC integrated encryption scheme; ephemeral key and tag are inside the ciphertext");
        add(AlgorithmId.SM2, "SM2 encryption", AlgorithmFamily.ASYMMETRIC, SecurityStatus.RECOMMENDED,
                256, 0, 0, ENC_DEC_WRAP, false, true, false, "GB/T 32918 SM2 public key encryption");
        add(AlgorithmId.ML_KEM_768, "ML-KEM-768", AlgorithmFamily.KEM, SecurityStatus.EXPERIMENTAL,
                0, 0, 0, ENC_DEC_WRAP, false, false, true, "Post-quantum KEM (reserved)");

        // Hash
        add(AlgorithmId.SHA_256, "SHA-256", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "FIPS 180-4");
        add(AlgorithmId.SHA_384, "SHA-384", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "FIPS 180-4");
        add(AlgorithmId.SHA_512, "SHA-512", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "FIPS 180-4");
        add(AlgorithmId.SHA3_256, "SHA3-256", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "FIPS 202");
        add(AlgorithmId.SHA3_512, "SHA3-512", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "FIPS 202");
        add(AlgorithmId.SHAKE_128, "SHAKE128", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "XOF; this library exposes a 32-byte digest");
        add(AlgorithmId.SHAKE_256, "SHAKE256", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), true, false, false, "XOF; this library exposes a 64-byte digest");
        add(AlgorithmId.BLAKE2B_256, "BLAKE2b-256", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), false, false, false, "Fast non-FIPS digest");
        add(AlgorithmId.BLAKE2B_512, "BLAKE2b-512", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), false, false, false, "Fast non-FIPS digest");
        add(AlgorithmId.BLAKE3_256, "BLAKE3-256", AlgorithmFamily.HASH, SecurityStatus.EXPERIMENTAL,
                0, 0, 0, Set.of(), false, false, false, "Optional; may not be available");
        add(AlgorithmId.SM3, "SM3", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), false, true, false, "GB/T 32905 SM3");
        add(AlgorithmId.MD5, "MD5", AlgorithmFamily.HASH, SecurityStatus.PROHIBITED,
                0, 0, 0, Set.of(), false, false, false, "Broken digest; always denied");
        add(AlgorithmId.SHA_1, "SHA-1", AlgorithmFamily.HASH, SecurityStatus.PROHIBITED,
                0, 0, 0, Set.of(), false, false, false, "Collision-broken; denied for security use");

        // MAC
        add(AlgorithmId.HMAC_SHA256, "HMAC-SHA256", AlgorithmFamily.MAC, SecurityStatus.RECOMMENDED,
                256, 0, 32, MAC_ONLY, true, false, false, "FIPS 198-1");
        add(AlgorithmId.HMAC_SHA384, "HMAC-SHA384", AlgorithmFamily.MAC, SecurityStatus.RECOMMENDED,
                256, 0, 48, MAC_ONLY, true, false, false, "FIPS 198-1");
        add(AlgorithmId.HMAC_SHA512, "HMAC-SHA512", AlgorithmFamily.MAC, SecurityStatus.RECOMMENDED,
                256, 0, 64, MAC_ONLY, true, false, false, "FIPS 198-1");
        add(AlgorithmId.HMAC_SM3, "HMAC-SM3", AlgorithmFamily.MAC, SecurityStatus.RECOMMENDED,
                256, 0, 32, MAC_ONLY, false, true, false, "HMAC built on SM3");
        add(AlgorithmId.CMAC_AES, "AES-CMAC", AlgorithmFamily.MAC, SecurityStatus.DEPRECATED,
                128, 0, 16, MAC_ONLY, true, false, false, "Legacy only; prefer HMAC");

        // Signature
        add(AlgorithmId.ED25519, "Ed25519", AlgorithmFamily.SIGNATURE, SecurityStatus.RECOMMENDED,
                256, 0, 64, SIGN_VERIFY, false, false, false, "RFC 8032");
        add(AlgorithmId.ED448, "Ed448", AlgorithmFamily.SIGNATURE, SecurityStatus.RECOMMENDED,
                456, 0, 114, SIGN_VERIFY, false, false, false, "RFC 8032");
        add(AlgorithmId.ECDSA_P256, "ECDSA P-256 with SHA-256", AlgorithmFamily.SIGNATURE,
                SecurityStatus.RECOMMENDED, 256, 0, 0, SIGN_VERIFY, true, false, false, "FIPS 186-5");
        add(AlgorithmId.ECDSA_P384, "ECDSA P-384 with SHA-384", AlgorithmFamily.SIGNATURE,
                SecurityStatus.RECOMMENDED, 384, 0, 0, SIGN_VERIFY, true, false, false, "FIPS 186-5");
        add(AlgorithmId.RSA_PSS, "RSA-PSS with SHA-256", AlgorithmFamily.SIGNATURE,
                SecurityStatus.RECOMMENDED, 2048, 0, 0, SIGN_VERIFY, true, false, false,
                "PSS padding; salt length equals digest length");
        add(AlgorithmId.RSA_PKCS1_SIGNATURE, "RSA PKCS#1 v1.5 signature", AlgorithmFamily.SIGNATURE,
                SecurityStatus.DEPRECATED, 2048, 0, 0, SIGN_VERIFY, true, false, false,
                "Legacy signatures; prefer RSA-PSS or Ed25519");
        add(AlgorithmId.DSA, "DSA", AlgorithmFamily.SIGNATURE, SecurityStatus.DEPRECATED,
                2048, 0, 0, SIGN_VERIFY, true, false, false, "Legacy signatures; prefer ECDSA/Ed25519");
        add(AlgorithmId.SM2_SIGNATURE, "SM2 signature", AlgorithmFamily.SIGNATURE,
                SecurityStatus.RECOMMENDED, 256, 0, 0, SIGN_VERIFY, false, true, false,
                "GB/T 32918 SM2 signature with SM3");
        add(AlgorithmId.ML_DSA_65, "ML-DSA-65", AlgorithmFamily.SIGNATURE, SecurityStatus.EXPERIMENTAL,
                0, 0, 0, SIGN_VERIFY, false, false, true, "Post-quantum signature (reserved)");

        // KDF
        add(AlgorithmId.ARGON2ID, "Argon2id", AlgorithmFamily.KDF, SecurityStatus.RECOMMENDED,
                0, 0, 0, DERIVE_ONLY, false, false, false, "RFC 9106 memory-hard password KDF");
        add(AlgorithmId.SCRYPT, "scrypt", AlgorithmFamily.KDF, SecurityStatus.RECOMMENDED,
                0, 0, 0, DERIVE_ONLY, false, false, false, "RFC 7914 memory-hard password KDF");
        add(AlgorithmId.BCRYPT, "bcrypt", AlgorithmFamily.KDF, SecurityStatus.DEPRECATED,
                0, 0, 0, DERIVE_ONLY, false, false, false, "Legacy password hashing only");
        add(AlgorithmId.PBKDF2, "PBKDF2-HMAC-SHA256", AlgorithmFamily.KDF, SecurityStatus.RECOMMENDED,
                0, 0, 0, DERIVE_ONLY, true, false, false, "FIPS-approved password KDF");
        add(AlgorithmId.HKDF, "HKDF-SHA256", AlgorithmFamily.KDF, SecurityStatus.RECOMMENDED,
                0, 0, 0, DERIVE_ONLY, true, false, false, "RFC 5869 key derivation");
    }

    private AlgorithmCatalog() {
    }

    private static void add(AlgorithmId id, String displayName, AlgorithmFamily family,
                            SecurityStatus status, int minKeyBits, int nonceBytes, int tagBytes,
                            Set<KeyUsage> usages, boolean fips, boolean gm, boolean pqc, String notes) {
        CATALOG.put(normalize(id.id()), new AlgorithmInfo(id, displayName, family, status,
                minKeyBits, nonceBytes, tagBytes, usages, fips, gm, pqc, notes));
    }

    private static String normalize(String id) {
        return id.trim().toUpperCase(Locale.ROOT);
    }

    public static Optional<AlgorithmInfo> lookup(String id) {
        return Optional.ofNullable(CATALOG.get(normalize(id)));
    }

    public static AlgorithmInfo infoOrUnknown(String id) {
        return lookup(id).orElseGet(() -> new AlgorithmInfo(AlgorithmId.of(id), id,
                AlgorithmFamily.UNKNOWN, SecurityStatus.UNKNOWN, 0, 0, 0, Set.of(),
                false, false, false, "Unregistered algorithm"));
    }

    /** Registers metadata supplied by a trusted extension provider. */
    public static synchronized void registerExternal(AlgorithmInfo info) {
        String key = normalize(info.id().id());
        AlgorithmInfo existing = CATALOG.get(key);
        if (existing != null && !existing.equals(info)) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Conflicting algorithm metadata for " + info.id().id());
        }
        CATALOG.putIfAbsent(key, info);
    }

    public static Set<AlgorithmInfo> all() {
        return Collections.unmodifiableSet(Set.copyOf(CATALOG.values()));
    }

    public static List<AlgorithmInfo> byFamily(AlgorithmFamily family) {
        List<AlgorithmInfo> result = new ArrayList<>();
        for (AlgorithmInfo info : CATALOG.values()) {
            if (info.family() == family) {
                result.add(info);
            }
        }
        return List.copyOf(result);
    }
}