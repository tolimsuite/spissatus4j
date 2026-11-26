package cn.tolim.spissatus4j.crypto.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.crypto.TestSupport;
import java.security.Provider;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class KdfFunctionTest {

    private static final JcaAlgorithmProvider PROVIDER = new JcaAlgorithmProvider();

    @Test
    void hkdfSha256Rfc5869CaseOne() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = TestSupport.hex("000102030405060708090a0b0c");
        byte[] info = TestSupport.hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] expected = TestSupport.hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");
        KdfFunction hkdf = PROVIDER.kdf(AlgorithmId.HKDF);
        byte[] derived = hkdf.derive(ikm, null, Salt.of(salt),
                new KdfParameters.Hkdf(42, info, "HmacSHA256"));
        assertArrayEquals(expected, derived);
        assertFalse(hkdf.needsRehash(new KdfParameters.Hkdf(42, info, "HmacSHA256")));
    }

    @Test
    void hkdfSha256Rfc5869CaseThreeEmptySaltAndInfo() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] expected = TestSupport.hex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8");
        byte[] derived = PROVIDER.kdf(AlgorithmId.HKDF).derive(ikm, null, Salt.empty(),
                new KdfParameters.Hkdf(42, new byte[0], "HmacSHA256"));
        assertArrayEquals(expected, derived);
    }

    @Test
    void hkdfSha512ProducesRequestedLength() {
        byte[] derived = PROVIDER.kdf(AlgorithmId.HKDF).derive(TestSupport.bytes(32, 5), null,
                Salt.of(TestSupport.bytes(16, 6)),
                new KdfParameters.Hkdf(100, TestSupport.bytes(7, 7), "HmacSHA512"));
        assertEquals(100, derived.length);
    }

    @Test
    void pbkdf2HmacSha256KnownVectors() {
        KdfFunction pbkdf2 = PROVIDER.kdf(AlgorithmId.PBKDF2);
        Salt salt = Salt.of("salt".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] oneIteration = pbkdf2.derive(null, "password".toCharArray(), salt,
                new KdfParameters.Pbkdf2(1, 32, "HmacSHA256"));
        assertArrayEquals(TestSupport.hex(
                        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
                oneIteration);

        byte[] twoIterations = pbkdf2.derive(null, "password".toCharArray(), salt,
                new KdfParameters.Pbkdf2(2, 32, "HmacSHA256"));
        assertArrayEquals(TestSupport.hex(
                        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
                twoIterations);
    }

    @Test
    void pbkdf2NeedsRehashUsesCurrentDefaultCost() {
        KdfFunction pbkdf2 = PROVIDER.kdf(AlgorithmId.PBKDF2);
        assertTrue(pbkdf2.needsRehash(new KdfParameters.Pbkdf2(1000, 32, "HmacSHA256")));
        assertTrue(pbkdf2.needsRehash(new KdfParameters.Pbkdf2(599_999, 32, "HmacSHA256")));
        assertFalse(pbkdf2.needsRehash(new KdfParameters.Pbkdf2(600_000, 32, "HmacSHA256")));
        assertFalse(pbkdf2.needsRehash(new KdfParameters.Pbkdf2(700_000, 32, "HmacSHA512")));
    }

    @Test
    void pbkdf2HonoursPrfAndOutputLength() {
        byte[] sha512Result = PROVIDER.kdf(AlgorithmId.PBKDF2).derive(null,
                "correct horse battery staple".toCharArray(), Salt.of(TestSupport.bytes(16, 8)),
                new KdfParameters.Pbkdf2(10, 64, "HmacSHA512"));
        assertEquals(64, sha512Result.length);
        byte[] sha256Result = PROVIDER.kdf(AlgorithmId.PBKDF2).derive(null,
                "correct horse battery staple".toCharArray(), Salt.of(TestSupport.bytes(16, 8)),
                new KdfParameters.Pbkdf2(10, 64, "HmacSHA256"));
        assertEquals(64, sha256Result.length);
        assertFalse(Arrays.equals(sha512Result, sha256Result));
    }

    @Test
    void pbkdf2RejectsProviderOutputShorterThanRequested() {
        SecretKeyFactory factory = stubFactory(new byte[32]);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> Pbkdf2Function.deriveWith(factory, "password".toCharArray(),
                        new byte[16], 1, 64));
        assertEquals(ErrorCode.PROVIDER_FAILURE, exception.errorCode());
    }

    @Test
    void pbkdf2RejectsProviderOutputLongerThanRequested() {
        SecretKeyFactory factory = stubFactory(new byte[96]);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> Pbkdf2Function.deriveWith(factory, "password".toCharArray(),
                        new byte[16], 1, 64));
        assertEquals(ErrorCode.PROVIDER_FAILURE, exception.errorCode());
    }

    @Test
    void pbkdf2LengthCheckWipesRejectedProviderOutput() {
        byte[] shortOutput = TestSupport.bytes(32, 23);
        assertThrows(CryptoException.class,
                () -> Pbkdf2Function.requireDerivedLength(shortOutput, 64));
        assertArrayEquals(new byte[32], shortOutput,
                "a rejected provider output must be wiped");
    }

    private static SecretKeyFactory stubFactory(byte[] output) {
        SecretKeyFactorySpi spi = new SecretKeyFactorySpi() {
            @Override
            protected SecretKey engineGenerateSecret(KeySpec keySpec) {
                return new SecretKeySpec(output, "PBKDF2WithHmacSHA512");
            }

            @Override
            protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) {
                throw new UnsupportedOperationException("not used");
            }

            @Override
            protected SecretKey engineTranslateKey(SecretKey key) {
                throw new UnsupportedOperationException("not used");
            }
        };
        return new StubSecretKeyFactory(spi);
    }

    private static final class StubSecretKeyFactory extends SecretKeyFactory {

        StubSecretKeyFactory(SecretKeyFactorySpi spi) {
            super(spi, STUB_PROVIDER, "PBKDF2WithHmacSHA512");
        }
    }

    private static final class StubProvider extends Provider {

        private static final long serialVersionUID = 1L;

        StubProvider() {
            super("SpissatusTestStub", "1.0", "PBKDF2 length-check test stub");
        }
    }

    private static final Provider STUB_PROVIDER = new StubProvider();

    @Test
    void kdfFunctionsRejectMismatchedParameters() {
        assertThrows(IllegalArgumentException.class,
                () -> PROVIDER.kdf(AlgorithmId.HKDF).derive(new byte[16], null, Salt.empty(),
                        new KdfParameters.Pbkdf2(1000, 32, "HmacSHA256")));
        assertThrows(IllegalArgumentException.class,
                () -> PROVIDER.kdf(AlgorithmId.PBKDF2).derive(null, "pw".toCharArray(),
                        Salt.of(TestSupport.bytes(16, 9)),
                        new KdfParameters.Hkdf(32, new byte[0], "HmacSHA256")));
    }
}
