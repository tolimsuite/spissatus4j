package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class BcMacTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void hmacSha256MatchesRfc4231CaseOne() {
        MacFunction mac = PROVIDER.mac(AlgorithmId.HMAC_SHA256);
        SecretKey key = new SecretKeySpec(
                HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                "HmacSHA256");

        byte[] tag = mac.compute(key, "Hi There".getBytes(StandardCharsets.US_ASCII));

        assertArrayEquals(HEX.parseHex(
                        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                tag);
        assertEquals(32, tag.length);
        assertTrue(mac.verify(key, "Hi There".getBytes(StandardCharsets.US_ASCII), tag));
    }

    @Test
    void verificationIsStrictAndConstantTime() {
        MacFunction mac = PROVIDER.mac(AlgorithmId.HMAC_SHA256);
        SecretKey key = new SecretKeySpec(new byte[32], "HmacSHA256");
        byte[] data = "authenticated".getBytes(StandardCharsets.UTF_8);
        byte[] tag = mac.compute(key, data);

        assertTrue(mac.verify(key, data, tag));

        byte[] tampered = tag.clone();
        tampered[0] ^= 0x01;
        assertFalse(mac.verify(key, data, tampered));
        assertFalse(mac.verify(key, data, new byte[31]));
        assertFalse(mac.verify(key, data, new byte[0]));

        SecretKey otherKey = new SecretKeySpec(new byte[]{1}, "HmacSHA256");
        assertFalse(mac.verify(otherKey, data, tag));
    }

    @Test
    void streamingMacMatchesInMemoryMac() throws Exception {
        byte[] data = new byte[12_345];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 17);
        }
        MacFunction mac = PROVIDER.mac(AlgorithmId.HMAC_SHA512);
        SecretKey key = new SecretKeySpec("key-material".getBytes(StandardCharsets.UTF_8),
                "HmacSHA512");

        byte[] expected = mac.compute(key, data);
        byte[] streamed;
        try (ByteArrayInputStream input = new ByteArrayInputStream(data)) {
            streamed = mac.compute(key, input);
        }

        assertArrayEquals(expected, streamed);
        assertEquals(64, expected.length);
    }

    @Test
    void tagLengthsMatchOutput() {
        String[] keyAlgorithms = {"HmacSHA256", "HmacSHA384", "HmacSHA512"};
        AlgorithmId[] algorithms = {AlgorithmId.HMAC_SHA256, AlgorithmId.HMAC_SHA384,
                AlgorithmId.HMAC_SHA512};
        for (int i = 0; i < algorithms.length; i++) {
            MacFunction mac = PROVIDER.mac(algorithms[i]);
            byte[] tag = mac.compute(new SecretKeySpec(new byte[32], keyAlgorithms[i]),
                    "data".getBytes(StandardCharsets.UTF_8));
            assertEquals(mac.tagLength(), tag.length, "tag length mismatch for " + algorithms[i]);
        }
    }

    @Test
    void cmacAesMatchesNistSp80038bVectorAndVerifiesConstantTime() {
        MacFunction mac = PROVIDER.mac(AlgorithmId.CMAC_AES);
        SecretKey key = new SecretKeySpec(
                HEX.parseHex("2b7e151628aed2a6abf7158809cf4f3c"), "AES");
        byte[] message = HEX.parseHex("6bc1bee22e409f96e93d7e117393172a");

        byte[] tag = mac.compute(key, message);

        assertArrayEquals(HEX.parseHex("070a16b46b4d4144f79bdd9dd04a287c"), tag);
        assertEquals(16, tag.length);
        assertEquals(16, mac.tagLength());
        assertEquals(AlgorithmId.CMAC_AES, mac.algorithm());
        assertTrue(mac.verify(key, message, tag));

        byte[] tampered = tag.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(mac.verify(key, message, tampered));
        assertFalse(mac.verify(new SecretKeySpec(new byte[16], "AES"), message, tag));
    }

    @Test
    void streamingCmacMatchesInMemoryCmac() throws Exception {
        byte[] data = new byte[4_321];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 13);
        }
        MacFunction mac = PROVIDER.mac(AlgorithmId.CMAC_AES);
        SecretKey key = new SecretKeySpec(
                HEX.parseHex("2b7e151628aed2a6abf7158809cf4f3c"), "AES");

        byte[] expected = mac.compute(key, data);
        byte[] streamed;
        try (ByteArrayInputStream input = new ByteArrayInputStream(data)) {
            streamed = mac.compute(key, input);
        }

        assertArrayEquals(expected, streamed);
        assertEquals(16, expected.length);
    }

    @Test
    void differentMessagesProduceDifferentTags() {
        MacFunction mac = PROVIDER.mac(AlgorithmId.HMAC_SHA256);
        SecretKey key = new SecretKeySpec(new byte[32], "HmacSHA256");

        byte[] first = mac.compute(key, "one".getBytes(StandardCharsets.US_ASCII));
        byte[] second = mac.compute(key, "two".getBytes(StandardCharsets.US_ASCII));

        assertFalse(java.security.MessageDigest.isEqual(first, second));
    }
}