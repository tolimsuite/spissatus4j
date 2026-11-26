package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.Test;

class BcKdfTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final HexFormat HEX = HexFormat.of();
    private static final String BCRYPT_ALPHABET =
            "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    @Test
    void argon2idIsDeterministicAndUsesRequiredParameters() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.ARGON2ID);
        KdfParameters.Argon2id parameters = new KdfParameters.Argon2id(65_536, 2, 1, 32, 19);
        Salt salt = Salt.of("somesalt".getBytes(StandardCharsets.UTF_8));
        char[] password = "password".toCharArray();
        try {
            byte[] first = kdf.derive(null, password, salt, parameters);
            byte[] second = kdf.derive(null, password, salt, parameters);

            assertEquals(32, first.length);
            assertArrayEquals(first, second);
            assertFalse(Arrays.equals(new byte[32], first));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void argon2idNeedsRehashDecisions() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.ARGON2ID);

        assertFalse(kdf.needsRehash(new KdfParameters.Argon2id(65_536, 3, 1, 32, 19)));
        assertTrue(kdf.needsRehash(new KdfParameters.Argon2id(32_768, 3, 1, 32, 19)));
        assertTrue(kdf.needsRehash(new KdfParameters.Argon2id(65_536, 2, 1, 32, 19)));
        assertTrue(kdf.needsRehash(new KdfParameters.Argon2id(65_536, 3, 1, 16, 19)));
        assertTrue(kdf.needsRehash(new KdfParameters.Argon2id(65_536, 3, 1, 32, 16)));
    }

    @Test
    void scryptMatchesRfc7914Vector() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.SCRYPT);
        KdfParameters.Scrypt parameters = new KdfParameters.Scrypt(1024, 8, 16, 64);
        char[] password = "password".toCharArray();
        try {
            byte[] derived = kdf.derive(null, password, Salt.of("NaCl".getBytes(StandardCharsets.US_ASCII)),
                    parameters);
            assertArrayEquals(HEX.parseHex(
                            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                                    + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
                    derived);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void scryptNeedsRehashAndLowCostRoundTrip() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.SCRYPT);
        assertFalse(kdf.needsRehash(new KdfParameters.Scrypt(32_768, 8, 1, 32)));
        assertTrue(kdf.needsRehash(new KdfParameters.Scrypt(16_384, 8, 1, 32)));
        assertTrue(kdf.needsRehash(new KdfParameters.Scrypt(32_768, 1, 1, 32)));
        assertTrue(kdf.needsRehash(new KdfParameters.Scrypt(32_768, 8, 1, 16)));

        char[] password = "roundtrip".toCharArray();
        try {
            byte[] first = kdf.derive(null, password, Salt.of("salty".getBytes(StandardCharsets.US_ASCII)),
                    new KdfParameters.Scrypt(16, 1, 1, 32));
            byte[] second = kdf.derive(null, password, Salt.of("salty".getBytes(StandardCharsets.US_ASCII)),
                    new KdfParameters.Scrypt(16, 1, 1, 32));
            assertArrayEquals(first, second);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void pbkdf2MatchesSha256VectorAndNeedsRehashBoundary() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.PBKDF2);
        char[] password = "password".toCharArray();
        try {
            byte[] derived = kdf.derive(null, password,
                    Salt.of("salt".getBytes(StandardCharsets.US_ASCII)),
                    new KdfParameters.Pbkdf2(1, 32, "HmacSHA256"));
            assertArrayEquals(HEX.parseHex(
                            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
                    derived);
        } finally {
            Arrays.fill(password, '\0');
        }

        assertFalse(kdf.needsRehash(new KdfParameters.Pbkdf2(600_000, 32, "HmacSHA256")));
        assertTrue(kdf.needsRehash(new KdfParameters.Pbkdf2(599_999, 32, "HmacSHA256")));
    }

    @Test
    void hkdfMatchesRfc5869TestCaseOne() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.HKDF);
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");
        byte[] expected = HEX.parseHex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");

        byte[] derived = kdf.derive(ikm, null, Salt.of(salt),
                new KdfParameters.Hkdf(42, info, "HmacSHA256"));

        assertArrayEquals(expected, derived);
    }

    @Test
    void hkdfIsRoutedThroughTheConfiguredProvider() {
        RecordingProvider recording = new RecordingProvider(PROVIDER.jcaProvider());
        BouncyCastleAlgorithmProvider provider = new BouncyCastleAlgorithmProvider(recording);
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);

        byte[] derived = provider.kdf(AlgorithmId.HKDF).derive(ikm, null,
                Salt.of(HEX.parseHex("000102030405060708090a0b0c")),
                new KdfParameters.Hkdf(42, HEX.parseHex("f0f1f2f3f4f5f6f7f8f9"), "HmacSHA256"));

        assertArrayEquals(HEX.parseHex(
                        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                + "34007208d5b887185865"),
                derived);
        assertTrue(recording.requested("KDF", "HKDF-SHA256"),
                "HKDF must be looked up from the configured provider");
    }

    @Test
    void hkdfSha512MatchesRfc5869CaseSixAndUsesConfiguredProvider() {
        RecordingProvider recording = new RecordingProvider(PROVIDER.jcaProvider());
        BouncyCastleAlgorithmProvider provider = new BouncyCastleAlgorithmProvider(recording);
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);

        byte[] derived = provider.kdf(AlgorithmId.HKDF).derive(ikm, null,
                Salt.of(HEX.parseHex("000102030405060708090a0b0c")),
                new KdfParameters.Hkdf(42, HEX.parseHex("f0f1f2f3f4f5f6f7f8f9"), "HmacSHA512"));

        assertArrayEquals(HEX.parseHex(
                        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793"
                                + "38da362cb8d9f925d7cb"),
                derived);
        assertTrue(recording.requested("KDF", "HKDF-SHA512"),
                "HKDF-SHA512 must be looked up from the configured provider");
    }

    @Test
    void hkdfEmptySaltMatchesRfc5869CaseThree() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);

        byte[] derived = PROVIDER.kdf(AlgorithmId.HKDF).derive(ikm, null, Salt.empty(),
                new KdfParameters.Hkdf(42, new byte[0], "HmacSHA256"));

        assertArrayEquals(HEX.parseHex(
                        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                                + "9d201395faa4b61a96c8"),
                derived);
    }

    @Test
    void fipsModeHkdfFailsClosedWhenProviderLacksKdf() {
        Provider emptyProvider = new Provider("empty-kdf-provider", "1.0", "no services") {
            private static final long serialVersionUID = 1L;
        };
        BouncyCastleAlgorithmProvider fips = new BouncyCastleAlgorithmProvider(emptyProvider, true);

        assertTrue(fips.supports(AlgorithmId.HKDF));
        CryptoException failure = assertThrows(CryptoException.class,
                () -> fips.kdf(AlgorithmId.HKDF).derive(new byte[32], null, Salt.empty(),
                        KdfParameters.hkdfDefault(new byte[0])));

        assertEquals(ErrorCode.PROVIDER_FAILURE, failure.errorCode());
        assertEquals("HKDF is unavailable", failure.getMessage());
    }

    @Test
    void hkdfRejectsMissingInputKeyMaterial() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.HKDF);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> kdf.derive(new byte[0], null, Salt.empty(),
                        KdfParameters.hkdfDefault(new byte[0])));

        assertEquals(ErrorCode.INVALID_PARAMETER, failure.errorCode());
        assertTrue(kdf.needsRehash(new KdfParameters.Hkdf(16, new byte[0], "HmacSHA256")));
        assertFalse(kdf.needsRehash(new KdfParameters.Hkdf(32, new byte[0], "HmacSHA256")));
    }

    @Test
    void mismatchedParameterTypesAreRejected() {
        CryptoException argon = assertThrows(CryptoException.class,
                () -> PROVIDER.kdf(AlgorithmId.ARGON2ID).derive(null, "pw".toCharArray(),
                        Salt.of("somesalt".getBytes(StandardCharsets.UTF_8)),
                        new KdfParameters.Scrypt(16, 1, 1, 32)));
        assertEquals(ErrorCode.INVALID_PARAMETER, argon.errorCode());

        CryptoException scrypt = assertThrows(CryptoException.class,
                () -> PROVIDER.kdf(AlgorithmId.SCRYPT).derive(null, "pw".toCharArray(),
                        Salt.of("salt".getBytes(StandardCharsets.US_ASCII)),
                        new KdfParameters.Argon2id(8, 1, 1, 32, 19)));
        assertEquals(ErrorCode.INVALID_PARAMETER, scrypt.errorCode());
    }

    @Test
    void saltAndPasswordValidationFailsClosed() {
        char[] password = "pw".toCharArray();
        try {
            CryptoException shortArgonSalt = assertThrows(CryptoException.class,
                    () -> PROVIDER.kdf(AlgorithmId.ARGON2ID).derive(null, password,
                            Salt.of(new byte[4]), new KdfParameters.Argon2id(8, 1, 1, 32, 19)));
            assertEquals(ErrorCode.INVALID_PARAMETER, shortArgonSalt.errorCode());

            CryptoException emptyScryptSalt = assertThrows(CryptoException.class,
                    () -> PROVIDER.kdf(AlgorithmId.SCRYPT).derive(null, password, Salt.empty(),
                            new KdfParameters.Scrypt(16, 1, 1, 32)));
            assertEquals(ErrorCode.INVALID_PARAMETER, emptyScryptSalt.errorCode());

            CryptoException emptyPbkdf2Salt = assertThrows(CryptoException.class,
                    () -> PROVIDER.kdf(AlgorithmId.PBKDF2).derive(null, password, Salt.empty(),
                            new KdfParameters.Pbkdf2(1, 32, "HmacSHA256")));
            assertEquals(ErrorCode.INVALID_PARAMETER, emptyPbkdf2Salt.errorCode());

            CryptoException nullPassword = assertThrows(CryptoException.class,
                    () -> PROVIDER.kdf(AlgorithmId.SCRYPT).derive(null, null,
                            Salt.of("salt".getBytes(StandardCharsets.US_ASCII)),
                            new KdfParameters.Scrypt(16, 1, 1, 32)));
            assertEquals(ErrorCode.INVALID_PARAMETER, nullPassword.errorCode());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void bcryptMatchesBouncyCastleModularCryptImplementation() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.BCRYPT);
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
        char[] password = "correct horse battery staple".toCharArray();
        try {
            byte[] raw = kdf.derive(null, password, Salt.of(salt),
                    new KdfParameters.Bcrypt(4));
            assertEquals(24, raw.length);

            String modular = "$2y$04$" + bcryptBase64(salt, 16) + bcryptBase64(raw, 23);
            assertEquals(60, modular.length());
            assertTrue(OpenBSDBCrypt.checkPassword(modular, password));
            assertFalse(OpenBSDBCrypt.checkPassword(modular, "wrong-password".toCharArray()));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void bcryptValidationAndRehash() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.BCRYPT);
        char[] password = "pw".toCharArray();
        try {
            CryptoException shortSalt = assertThrows(CryptoException.class,
                    () -> kdf.derive(null, password, Salt.of(new byte[8]),
                            new KdfParameters.Bcrypt(4)));
            assertEquals(ErrorCode.INVALID_PARAMETER, shortSalt.errorCode());

            assertTrue(kdf.needsRehash(new KdfParameters.Bcrypt(4)));
            assertFalse(kdf.needsRehash(new KdfParameters.Bcrypt(12)));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    void bcryptPasswordLimitIsEnforced() {
        KdfFunction kdf = PROVIDER.kdf(AlgorithmId.BCRYPT);
        char[] password = new char[80];
        Arrays.fill(password, 'a');
        try {
            CryptoException failure = assertThrows(CryptoException.class,
                    () -> kdf.derive(null, password,
                            Salt.of(HEX.parseHex("000102030405060708090a0b0c0d0e0f")),
                            new KdfParameters.Bcrypt(4)));
            assertEquals(ErrorCode.INVALID_PARAMETER, failure.errorCode());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Encodes bytes using the bcrypt base64 alphabet without padding. */
    private static String bcryptBase64(byte[] data, int length) {
        StringBuilder encoded = new StringBuilder(31);
        for (int i = 0; i < length; i += 3) {
            int b1 = data[i] & 0xff;
            int b2 = i + 1 < length ? data[i + 1] & 0xff : 0;
            int b3 = i + 2 < length ? data[i + 2] & 0xff : 0;
            encoded.append(BCRYPT_ALPHABET.charAt((b1 >>> 2) & 0x3f));
            encoded.append(BCRYPT_ALPHABET.charAt(((b1 << 4) | (b2 >>> 4)) & 0x3f));
            if (i + 1 < length) {
                encoded.append(BCRYPT_ALPHABET.charAt(((b2 << 2) | (b3 >>> 6)) & 0x3f));
            }
            if (i + 2 < length) {
                encoded.append(BCRYPT_ALPHABET.charAt(b3 & 0x3f));
            }
        }
        return encoded.toString();
    }
}