package cn.tolim.spissatus4j.envelope.internal;

/**
 * Hard structural limits for envelope codecs and validation. These are
 * internal defaults; the service can be configured with a tighter maximum
 * encoded size for decoded input.
 */
public final class EnvelopeLimits {

    /** Default cap for a serialized envelope (256 MiB). */
    public static final int DEFAULT_MAX_BYTES = 268_435_456;

    /** A TLV header must never exceed one mebibyte. */
    public static final int MAX_HEADER_BYTES = 1_048_576;

    public static final int MAX_ATTRIBUTES = 64;
    public static final int MAX_ATTRIBUTE_KEY_BYTES = 128;
    public static final int MAX_ATTRIBUTE_VALUE_BYTES = 4096;

    /** Largest known parameter set (Argon2id) has five entries. */
    public static final int MAX_KDF_PARAMETERS = 16;

    /** SHA-256 header hash carried by version 2 envelopes. */
    public static final int MAX_HEADER_HASH_BYTES = 32;

    private EnvelopeLimits() {
    }
}