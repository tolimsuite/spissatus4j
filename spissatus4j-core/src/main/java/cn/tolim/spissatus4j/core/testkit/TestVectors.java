package cn.tolim.spissatus4j.core.testkit;

import java.nio.charset.StandardCharsets;

/**
 * Small known-answer constants for self-checks and tests.
 *
 * <p>These values are public NIST/RFC test vectors and are not secret. The
 * testkit package is production code so other modules can reuse it without a
 * test-fixtures dependency; it contains no key material.</p>
 */
public final class TestVectors {

    public static final byte[] SHA256_ABC =
            TestSupport.hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    public static final byte[] SHA3_256_ABC =
            TestSupport.hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    public static final byte[] SM3_ABC =
            TestSupport.hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    public static final byte[] AES_128_GCM_KEY =
            TestSupport.hex("00000000000000000000000000000000");
    public static final byte[] AES_128_GCM_NONCE =
            TestSupport.hex("000000000000000000000000");
    public static final byte[] AES_128_GCM_EMPTY_TAG =
            TestSupport.hex("58e2fccefa7e3061367f1d57a4e7455a");

    public static final byte[] HMAC_SHA256_RFC4231_KEY =
            TestSupport.hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    public static final byte[] HMAC_SHA256_RFC4231_DATA =
            "Hi There".getBytes(StandardCharsets.UTF_8);
    public static final byte[] HMAC_SHA256_RFC4231_TAG =
            TestSupport.hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    public static final byte[] SM4_ECB_KEY =
            TestSupport.hex("0123456789abcdeffedcba9876543210");
    public static final byte[] SM4_ECB_PLAINTEXT =
            TestSupport.hex("0123456789abcdeffedcba9876543210");
    public static final byte[] SM4_ECB_CIPHERTEXT =
            TestSupport.hex("681edf34d206965e86b3e94f536e4246");

    private TestVectors() {
    }
}