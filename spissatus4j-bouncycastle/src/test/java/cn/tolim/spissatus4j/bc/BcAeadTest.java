package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class BcAeadTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final HexFormat HEX = HexFormat.of();

    private static SecretKey aesKey() {
        return new SecretKeySpec(HEX.parseHex("000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"), "AES");
    }

    private static SecretKey chachaKey() {
        return new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII),
                "ChaCha20");
    }

    @Test
    void aesGcmRoundTripWithAad() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        byte[] plaintext = "confidential payload".getBytes(StandardCharsets.UTF_8);
        byte[] nonceBytes = "unique-nonce".getBytes(StandardCharsets.US_ASCII);
        AAD aad = AAD.ofUtf8("tenant=acme");

        AeadResult result = cipher.encrypt(aesKey(), plaintext, Nonce.of(nonceBytes), aad);

        assertArrayEquals(nonceBytes, result.nonce().asBytes());
        assertEquals(plaintext.length, result.ciphertext().length);
        assertEquals(16, result.tag().length);
        assertFalse(Arrays.equals(plaintext, result.ciphertext()));
        byte[] decrypted = cipher.decrypt(aesKey(), result.nonce(), result.ciphertext(),
                result.tag(), aad);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void aesGcmMatchesNistVector() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        SecretKey key = new SecretKeySpec(new byte[16], "AES");
        Nonce nonce = Nonce.of(new byte[12]);
        byte[] plaintext = new byte[16];

        AeadResult result = cipher.encrypt(key, plaintext, nonce, AAD.empty());

        assertArrayEquals(HEX.parseHex("0388dace60b6a392f328c2b971b2fe78"),
                result.ciphertext());
        assertArrayEquals(HEX.parseHex("ab6e47d42cec13bdf53a67b21257bddf"), result.tag());
        assertArrayEquals(plaintext, cipher.decrypt(key, nonce, result.ciphertext(),
                result.tag(), AAD.empty()));
    }

    @Test
    void aesGcmTamperedTagFailsClosed() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        byte[] nonceBytes = new byte[12];
        AAD aad = AAD.empty();
        AeadResult result = cipher.encrypt(aesKey(), "data".getBytes(StandardCharsets.UTF_8),
                Nonce.of(nonceBytes), aad);
        byte[] tamperedTag = result.tag();
        tamperedTag[tamperedTag.length - 1] ^= 0x01;

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(aesKey(), Nonce.of(nonceBytes), result.ciphertext(),
                        tamperedTag, aad));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void aesGcmWrongAadAndWrongKeyFailClosed() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce nonce = Nonce.of(new byte[12]);
        AeadResult result = cipher.encrypt(aesKey(), "data".getBytes(StandardCharsets.UTF_8),
                nonce, AAD.ofUtf8("right-aad"));

        CryptoException wrongAad = assertThrows(CryptoException.class,
                () -> cipher.decrypt(aesKey(), nonce, result.ciphertext(), result.tag(),
                        AAD.ofUtf8("wrong-aad")));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, wrongAad.errorCode());

        SecretKey otherKey = new SecretKeySpec(new byte[32], "AES");
        CryptoException wrongKey = assertThrows(CryptoException.class,
                () -> cipher.decrypt(otherKey, nonce, result.ciphertext(), result.tag(),
                        AAD.ofUtf8("right-aad")));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, wrongKey.errorCode());
    }

    @Test
    void chacha20Poly1305RoundTripAndTamperDetection() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.CHACHA20_POLY1305);
        byte[] plaintext = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
        Nonce nonce = Nonce.of("0123456789ab".getBytes(StandardCharsets.US_ASCII));
        AAD aad = AAD.ofUtf8("header");

        AeadResult result = cipher.encrypt(chachaKey(), plaintext, nonce, aad);
        assertArrayEquals(plaintext, cipher.decrypt(chachaKey(), nonce, result.ciphertext(),
                result.tag(), aad));

        byte[] tampered = result.ciphertext();
        tampered[0] ^= 0x01;
        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(chachaKey(), nonce, tampered, result.tag(), aad));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
    }

    @Test
    void chacha20Poly1305InteroperatesWithSunJce() throws Exception {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.CHACHA20_POLY1305);
        SecretKey key = new SecretKeySpec(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII),
                "ChaCha20");
        byte[] nonceBytes = "poly-nonce-1".getBytes(StandardCharsets.US_ASCII);
        byte[] aad = "chacha-interop".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "ChaCha20-Poly1305 interoperability".getBytes(StandardCharsets.UTF_8);

        Cipher jdk = Cipher.getInstance("ChaCha20-Poly1305", "SunJCE");
        jdk.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonceBytes));
        jdk.updateAAD(aad);
        byte[] jdkSealed = jdk.doFinal(plaintext);
        byte[] jdkCiphertext = Arrays.copyOf(jdkSealed, jdkSealed.length - 16);
        byte[] jdkTag = Arrays.copyOfRange(jdkSealed, jdkSealed.length - 16, jdkSealed.length);
        assertArrayEquals(plaintext, cipher.decrypt(key, Nonce.of(nonceBytes), jdkCiphertext,
                jdkTag, AAD.of(aad)));

        AeadResult ours = cipher.encrypt(key, plaintext, Nonce.of(nonceBytes), AAD.of(aad));
        byte[] combined = new byte[ours.ciphertext().length + ours.tag().length];
        System.arraycopy(ours.ciphertext(), 0, combined, 0, ours.ciphertext().length);
        System.arraycopy(ours.tag(), 0, combined, ours.ciphertext().length, ours.tag().length);
        jdk.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonceBytes));
        jdk.updateAAD(aad);
        assertArrayEquals(plaintext, jdk.doFinal(combined));
    }

    @Test
    void emptyPlaintextProducesTagOnly() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce nonce = Nonce.of(new byte[12]);

        AeadResult result = cipher.encrypt(aesKey(), new byte[0], nonce, AAD.empty());

        assertEquals(0, result.ciphertext().length);
        assertEquals(16, result.tag().length);
        assertArrayEquals(new byte[0], cipher.decrypt(aesKey(), nonce, result.ciphertext(),
                result.tag(), AAD.empty()));
    }

    @Test
    void invalidNonceLengthIsRejected() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce shortNonce = Nonce.of(new byte[11]);

        CryptoException encryptFailure = assertThrows(CryptoException.class,
                () -> cipher.encrypt(aesKey(), new byte[1], shortNonce, AAD.empty()));
        assertEquals(ErrorCode.NONCE_INVALID, encryptFailure.errorCode());

        CryptoException decryptFailure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(aesKey(), shortNonce, new byte[1], new byte[16], AAD.empty()));
        assertEquals(ErrorCode.NONCE_INVALID, decryptFailure.errorCode());
    }

    @Test
    void invalidTagLengthIsRejected() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(aesKey(), Nonce.of(new byte[12]), new byte[0],
                        new byte[15], AAD.empty()));

        assertEquals(ErrorCode.TAG_INVALID, failure.errorCode());
    }
}