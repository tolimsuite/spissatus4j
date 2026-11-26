package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class BcHashTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] ABC = "abc".getBytes(StandardCharsets.US_ASCII);

    @Test
    void sha256AndSha3KnownAnswers() {
        assertArrayEquals(HEX.parseHex(
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                PROVIDER.hash(AlgorithmId.SHA_256).digest(ABC));
        assertArrayEquals(HEX.parseHex(
                        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
                PROVIDER.hash(AlgorithmId.SHA3_256).digest(ABC));
        assertArrayEquals(HEX.parseHex(
                        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                                + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
                PROVIDER.hash(AlgorithmId.SHA3_512).digest(ABC));
    }

    @Test
    void blake2b512MatchesRfc7693Vector() {
        byte[] digest = PROVIDER.hash(AlgorithmId.BLAKE2B_512).digest(ABC);

        assertArrayEquals(HEX.parseHex(
                        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d"
                                + "17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
                digest);
    }

    @Test
    void blake2b256MatchesBouncyCastleJcaImplementation() throws Exception {
        byte[] data = "BLAKE2b-256 consistency".getBytes(StandardCharsets.UTF_8);
        byte[] direct = PROVIDER.hash(AlgorithmId.BLAKE2B_256).digest(data);
        byte[] jca = MessageDigest.getInstance("BLAKE2B-256", PROVIDER.jcaProvider()).digest(data);

        assertEquals(32, direct.length);
        assertArrayEquals(jca, direct);
    }

    @Test
    void shakeFixedOutputMatchesFips202Vectors() {
        byte[] shake128 = PROVIDER.hash(AlgorithmId.SHAKE_128).digest(new byte[0]);
        byte[] shake256 = PROVIDER.hash(AlgorithmId.SHAKE_256).digest(new byte[0]);

        assertArrayEquals(HEX.parseHex(
                        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
                shake128);
        assertArrayEquals(HEX.parseHex(
                        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                                + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"),
                shake256);
    }

    @Test
    void streamingDigestMatchesInMemoryDigest() throws Exception {
        byte[] data = new byte[20_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31);
        }
        for (AlgorithmId algorithm : new AlgorithmId[]{
                AlgorithmId.SHA_256, AlgorithmId.SHAKE_128, AlgorithmId.BLAKE2B_512}) {
            HashFunction hash = PROVIDER.hash(algorithm);
            byte[] expected = hash.digest(data);
            byte[] streamed;
            try (InputStream input = new ByteArrayInputStream(data)) {
                streamed = hash.digest(input);
            }
            assertArrayEquals(expected, streamed, "stream mismatch for " + algorithm);
        }
    }

    @Test
    void digestLengthsMatchActualOutput() {
        for (AlgorithmId algorithm : new AlgorithmId[]{
                AlgorithmId.SHA_256, AlgorithmId.SHA_384, AlgorithmId.SHA_512,
                AlgorithmId.SHA3_256, AlgorithmId.SHA3_512,
                AlgorithmId.SHAKE_128, AlgorithmId.SHAKE_256,
                AlgorithmId.BLAKE2B_256, AlgorithmId.BLAKE2B_512}) {
            HashFunction hash = PROVIDER.hash(algorithm);
            assertEquals(hash.digestLength(),
                    hash.digest("length".getBytes(StandardCharsets.US_ASCII)).length,
                    "length mismatch for " + algorithm);
        }
    }

    @Test
    void shakeAndBlake2AreRoutedThroughTheConfiguredProvider() {
        RecordingProvider recording = new RecordingProvider(PROVIDER.jcaProvider());
        BouncyCastleAlgorithmProvider provider = new BouncyCastleAlgorithmProvider(recording);

        for (AlgorithmId algorithm : new AlgorithmId[]{
                AlgorithmId.SHAKE_128, AlgorithmId.SHAKE_256,
                AlgorithmId.BLAKE2B_256, AlgorithmId.BLAKE2B_512}) {
            HashFunction hash = provider.hash(algorithm);
            assertEquals(hash.digestLength(), hash.digest(ABC).length,
                    "digest length mismatch for " + algorithm);
        }

        assertTrue(recording.requested("MessageDigest", "SHAKE128-256"),
                "SHAKE128 must be looked up from the configured provider");
        assertTrue(recording.requested("MessageDigest", "SHAKE256-512"),
                "SHAKE256 must be looked up from the configured provider");
        assertTrue(recording.requested("MessageDigest", "BLAKE2B-256"),
                "BLAKE2b-256 must be looked up from the configured provider");
        assertTrue(recording.requested("MessageDigest", "BLAKE2B-512"),
                "BLAKE2b-512 must be looked up from the configured provider");
    }

    @Test
    void fipsModeFailsClosedWhenProviderLacksShake() {
        Provider emptyProvider = new Provider("empty-hash-provider", "1.0", "no services") {
            private static final long serialVersionUID = 1L;
        };
        BouncyCastleAlgorithmProvider fips = new BouncyCastleAlgorithmProvider(emptyProvider, true);

        assertTrue(fips.supports(AlgorithmId.SHAKE_256));
        CryptoException failure = assertThrows(CryptoException.class,
                () -> fips.hash(AlgorithmId.SHAKE_256).digest(ABC));

        assertEquals(ErrorCode.PROVIDER_FAILURE, failure.errorCode());
        assertFalse(failure.getMessage().contains("SHAKE"));
        assertFalse(fips.supports(AlgorithmId.BLAKE2B_512));
    }

    @Test
    void streamReadFailuresArePropagated() {
        InputStream failing = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("synthetic read failure");
            }
        };
        HashFunction hash = PROVIDER.hash(AlgorithmId.SHA_256);

        assertThrows(IOException.class, () -> hash.digest(failing));
    }
}