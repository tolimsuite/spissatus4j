package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.crypto.AAD;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

/** Shared structural limits for the unified entry points. */
final class UnifiedLimits {

    static final int MAX_USER_AAD_BYTES = 1_048_576 - 128;
    static final int MAX_CANDIDATES = 32;
    static final int MAX_ATTRIBUTES = 64;
    static final int MAX_ATTRIBUTE_KEY_BYTES = 128;
    static final int MAX_ATTRIBUTE_VALUE_BYTES = 4096;

    private static final String RESERVED_PREFIX = "spissatus.";
    private static final String RESERVED_PREFIX_ALT = "spi4.";

    private UnifiedLimits() {
    }

    static void requirePlaintext(byte[] plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
    }

    static void requireAad(AAD aad) {
        Objects.requireNonNull(aad, "aad");
        if (aad.length() > MAX_USER_AAD_BYTES) {
            throw new IllegalArgumentException("AAD exceeds the unified entry limit");
        }
    }

    static void requireAttributes(Map<String, String> attributes) {
        Objects.requireNonNull(attributes, "attributes");
        if (attributes.size() > MAX_ATTRIBUTES) {
            throw new IllegalArgumentException("Too many attributes");
        }
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = Objects.requireNonNull(entry.getKey(), "attribute key");
            String value = Objects.requireNonNull(entry.getValue(), "attribute value");
            if (key.startsWith(RESERVED_PREFIX) || key.startsWith(RESERVED_PREFIX_ALT)) {
                throw new IllegalArgumentException("Reserved attribute prefix");
            }
            if (!isWellFormed(key) || !isWellFormed(value)) {
                throw new IllegalArgumentException("Attributes must be well-formed Unicode");
            }
            int keyBytes = utf8Length(key);
            if (keyBytes < 1 || keyBytes > MAX_ATTRIBUTE_KEY_BYTES
                    || utf8Length(value) > MAX_ATTRIBUTE_VALUE_BYTES) {
                throw new IllegalArgumentException("Attribute length is invalid");
            }
        }
    }

    static boolean isWellFormed(String value) {
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    return false;
                }
                index++;
            } else if (Character.isLowSurrogate(current)) {
                return false;
            }
        }
        return true;
    }

    static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }
}