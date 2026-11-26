package cn.tolim.spissatus4j.key.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.KeyType;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/** Shared, non-secret key metadata helpers. */
public final class KeySupport {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<KeyUsage> PROTECTING =
            EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.SIGN, KeyUsage.WRAP, KeyUsage.MAC);
    private static final Set<KeyUsage> PROCESSING =
            EnumSet.of(KeyUsage.DECRYPT, KeyUsage.VERIFY, KeyUsage.UNWRAP);

    private KeySupport() {
    }

    public static KeyId randomKeyId() {
        byte[] value = new byte[16];
        RANDOM.nextBytes(value);
        return KeyId.of("key-" + HexFormat.of().formatHex(value));
    }

    public static byte[] randomBytes(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    public static boolean isAsymmetric(KeyType type) {
        return switch (type) {
            case RSA, EC, ED25519, ED448, SM2, KEM -> true;
            case AES, SM4, HMAC, SYMMETRIC, RAW -> false;
        };
    }

    public static boolean usesSecretKeyMaterial(KeyType type) {
        return !isAsymmetric(type);
    }

    public static boolean isProtecting(KeyUsage usage) {
        return PROTECTING.contains(usage);
    }

    public static boolean isProcessing(KeyUsage usage) {
        return PROCESSING.contains(usage);
    }

    /** Auto-adds the complementary usage described by the module contract. */
    public static Set<KeyUsage> effectiveUsages(KeyType type, Set<KeyUsage> requested) {
        LinkedHashSet<KeyUsage> usages = new LinkedHashSet<>(requested);
        if (isAsymmetric(type)) {
            if (usages.contains(KeyUsage.SIGN)) {
                usages.add(KeyUsage.VERIFY);
            }
            if (usages.contains(KeyUsage.ENCRYPT)) {
                usages.add(KeyUsage.DECRYPT);
            }
        } else if (usages.contains(KeyUsage.ENCRYPT)) {
            usages.add(KeyUsage.DECRYPT);
        }
        return Set.copyOf(usages);
    }

    /** Rejects type/algorithm mismatches before any key material is created. */
    public static void validateTypeAlgorithm(KeyType type, AlgorithmId algorithm) {
        if (!algorithm.isKnown()) {
            throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Algorithm is not registered: " + algorithm.id());
        }
        boolean matches = switch (type) {
            case AES -> isAesAlgorithm(algorithm);
            case SM4 -> isSm4Algorithm(algorithm);
            case HMAC -> isHmacAlgorithm(algorithm);
            case RSA -> isRsaAlgorithm(algorithm);
            case EC -> isEcAlgorithm(algorithm);
            case ED25519 -> algorithm.equals(AlgorithmId.ED25519);
            case ED448 -> algorithm.equals(AlgorithmId.ED448);
            case SM2 -> algorithm.equals(AlgorithmId.SM2) || algorithm.equals(AlgorithmId.SM2_SIGNATURE);
            case KEM -> algorithm.equals(AlgorithmId.ML_KEM_768);
            case SYMMETRIC, RAW -> isGenericSecretAlgorithm(algorithm);
        };
        if (!matches) {
            throw new KeyException(ErrorCode.INVALID_PARAMETER,
                    "Key type does not match algorithm " + algorithm.id());
        }
    }

    private static boolean isAesAlgorithm(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.AES_GCM) || algorithm.equals(AlgorithmId.AES_CBC)
                || algorithm.equals(AlgorithmId.AES_CTR) || algorithm.equals(AlgorithmId.AES_CFB)
                || algorithm.equals(AlgorithmId.AES_OFB) || algorithm.equals(AlgorithmId.AES_KW)
                || algorithm.equals(AlgorithmId.AES_ECB);
    }

    private static boolean isSm4Algorithm(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.SM4) || algorithm.equals(AlgorithmId.SM4_GCM)
                || algorithm.equals(AlgorithmId.SM4_CBC) || algorithm.equals(AlgorithmId.SM4_CTR)
                || algorithm.equals(AlgorithmId.SM4_ECB);
    }

    private static boolean isHmacAlgorithm(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.HMAC_SHA256) || algorithm.equals(AlgorithmId.HMAC_SHA384)
                || algorithm.equals(AlgorithmId.HMAC_SHA512) || algorithm.equals(AlgorithmId.HMAC_SM3);
    }

    private static boolean isRsaAlgorithm(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.RSA_OAEP) || algorithm.equals(AlgorithmId.RSA_PKCS1)
                || algorithm.equals(AlgorithmId.RSA_PSS)
                || algorithm.equals(AlgorithmId.RSA_PKCS1_SIGNATURE);
    }

    private static boolean isEcAlgorithm(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.ECDSA_P256) || algorithm.equals(AlgorithmId.ECDSA_P384)
                || algorithm.equals(AlgorithmId.ECIES);
    }

    private static boolean isGenericSecretAlgorithm(AlgorithmId algorithm) {
        AlgorithmFamily family = algorithm.family();
        return family == AlgorithmFamily.SYMMETRIC || family == AlgorithmFamily.AEAD
                || family == AlgorithmFamily.MAC;
    }

    public static String jcaKeyAlgorithm(AlgorithmId algorithm, KeyType type) {
        if (isAesAlgorithm(algorithm) || algorithm.equals(AlgorithmId.CMAC_AES)) {
            return "AES";
        }
        if (isSm4Algorithm(algorithm)) {
            return "SM4";
        }
        if (algorithm.equals(AlgorithmId.CHACHA20_POLY1305)) {
            return "ChaCha20";
        }
        if (algorithm.equals(AlgorithmId.HMAC_SHA256)) {
            return "HmacSHA256";
        }
        if (algorithm.equals(AlgorithmId.HMAC_SHA384)) {
            return "HmacSHA384";
        }
        if (algorithm.equals(AlgorithmId.HMAC_SHA512)) {
            return "HmacSHA512";
        }
        if (algorithm.equals(AlgorithmId.HMAC_SM3)) {
            return "HmacSM3";
        }
        if (isRsaAlgorithm(algorithm)) {
            return "RSA";
        }
        if (isEcAlgorithm(algorithm) || algorithm.equals(AlgorithmId.SM2)
                || algorithm.equals(AlgorithmId.SM2_SIGNATURE)) {
            return "EC";
        }
        if (algorithm.equals(AlgorithmId.ED25519)) {
            return "Ed25519";
        }
        if (algorithm.equals(AlgorithmId.ED448)) {
            return "Ed448";
        }
        return type == KeyType.HMAC ? "HmacSHA256" : algorithm.id();
    }

    public static String keyFactoryAlgorithm(KeyType type) {
        return switch (type) {
            case RSA -> "RSA";
            case EC, SM2 -> "EC";
            case ED25519 -> "Ed25519";
            case ED448 -> "Ed448";
            case AES, SM4, HMAC, SYMMETRIC, RAW, KEM -> type.name();
        };
    }

    /** Returns a KeyFactory, preferring the Bouncy Castle provider when registered. */
    public static KeyFactory keyFactory(KeyType type) {
        String algorithm = keyFactoryAlgorithm(type);
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException first) {
            Provider bc = Security.getProvider("BC");
            if (bc != null) {
                try {
                    return KeyFactory.getInstance(algorithm, bc);
                } catch (NoSuchAlgorithmException ignored) {
                    // fall through to the generic failure below
                }
            }
            throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Key factory is not available for type " + type.name());
        }
    }

    public static String fingerprint(byte[] material) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(material));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException(ErrorCode.INTERNAL_ERROR, "SHA-256 is not available");
        }
    }

    public static String keyStoreAlias(KeyId keyId, KeyVersion version) {
        // JCEKS lower-cases aliases; hex preserves KeyId identity and is safe on
        // case-insensitive stores.
        return HexFormat.of().formatHex(keyId.value().getBytes(StandardCharsets.UTF_8))
                + "-v" + version.value();
    }

    /** Lifecycle transition table from the module contract. */
    public static boolean canTransition(KeyState from, KeyState to) {
        return switch (from) {
            case PRE_ACTIVATION -> to == KeyState.ACTIVE || to == KeyState.DESTROYED
                    || to == KeyState.COMPROMISED;
            case ACTIVE -> to == KeyState.DEACTIVATED || to == KeyState.COMPROMISED
                    || to == KeyState.REVOKED || to == KeyState.DESTROYED;
            case DEACTIVATED -> to == KeyState.ACTIVE || to == KeyState.REVOKED
                    || to == KeyState.COMPROMISED || to == KeyState.DESTROYED;
            case COMPROMISED -> to == KeyState.REVOKED || to == KeyState.DESTROYED_COMPROMISED
                    || to == KeyState.DESTROYED;
            case REVOKED -> to == KeyState.DESTROYED;
            case DESTROYED, DESTROYED_COMPROMISED -> false;
        };
    }

    /** Sanitizes a caller-supplied reason before it is placed in an audit record. */
    public static String sanitizeReason(String reason) {
        StringBuilder sanitized = new StringBuilder();
        boolean lastWasSpace = false;
        for (int i = 0; i < reason.length() && sanitized.length() < 160; i++) {
            char current = reason.charAt(i);
            char replacement = current < 0x20 || current == 0x7f ? ' ' : current;
            boolean space = replacement == ' ';
            if (space && lastWasSpace) {
                continue;
            }
            sanitized.append(replacement);
            lastWasSpace = space;
        }
        String result = sanitized.toString().trim();
        return result.isEmpty() ? "unspecified" : result;
    }

    /** Builds the environment variable suffix for a key id and version. */
    public static String environmentSuffix(KeyId keyId) {
        StringBuilder sanitized = new StringBuilder();
        String raw = keyId.value().toUpperCase(Locale.ROOT);
        for (int i = 0; i < raw.length(); i++) {
            char current = raw.charAt(i);
            boolean alphanumeric = (current >= 'A' && current <= 'Z') || (current >= '0' && current <= '9');
            sanitized.append(alphanumeric ? current : '_');
        }
        if (sanitized.isEmpty() || (sanitized.charAt(0) >= '0' && sanitized.charAt(0) <= '9')) {
            sanitized.insert(0, "K");
        }
        if (sanitized.charAt(0) == '_') {
            sanitized.insert(0, "K");
        }
        return sanitized.toString();
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static KeyException providerFailure(String message) {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, message);
    }
}