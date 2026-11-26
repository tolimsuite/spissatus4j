package cn.tolim.spissatus4j.crypto.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.crypto.TestSupport;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class AeadCipherTest {

    private static final JcaAlgorithmProvider PROVIDER = new JcaAlgorithmProvider();

    @Test
    void aesGcmMatchesNistEmptyPlaintextVector() {
        SecretKey key = new javax.crypto.spec.SecretKeySpec(new byte[16], "AES");
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        AeadCipher.AeadResult result = cipher.encrypt(key, new byte[0],
                Nonce.of(new byte[12]), AAD.empty());
        assertArrayEquals(new byte[0], result.ciphertext());
        assertArrayEquals(TestSupport.hex("58e2fccefa7e3061367f1d57a4e7455a"), result.tag());
        assertArrayEquals(new byte[0], cipher.decrypt(key, Nonce.of(new byte[12]),
                new byte[0], result.tag(), AAD.empty()));
        assertEquals(12, cipher.nonceLength());
        assertEquals(16, cipher.tagLength());
    }

    @Test
    void aesGcmRoundtripWithAad() {
        SecretKey key = TestSupport.aesKey(32, 11);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        byte[] plaintext = TestSupport.bytes(4096, 12);
        AAD aad = AAD.ofUtf8("tenant-42/record-7");
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 13));
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
        assertArrayEquals(plaintext, cipher.decrypt(key, nonce, encrypted.ciphertext(),
                encrypted.tag(), aad));
    }

    @Test
    void aesGcmAadMismatchFailsAuthentication() {
        SecretKey key = TestSupport.aesKey(16, 21);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 22));
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, TestSupport.bytes(64, 23), nonce,
                AAD.ofUtf8("original-aad"));

        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, encrypted.ciphertext(), encrypted.tag(),
                        AAD.ofUtf8("different-aad")));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
        assertEquals("Cryptographic authentication failed", exception.getMessage());
    }

    @Test
    void aesGcmTagTamperFailsAuthentication() {
        SecretKey key = TestSupport.aesKey(16, 31);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 32));
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, TestSupport.bytes(100, 33), nonce,
                AAD.empty());
        byte[] tampered = encrypted.tag();
        tampered[0] ^= 0x01;

        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, encrypted.ciphertext(), tampered, AAD.empty()));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
    }

    @Test
    void aesGcmCiphertextTamperFailsAuthentication() {
        SecretKey key = TestSupport.aesKey(16, 41);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 42));
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, TestSupport.bytes(100, 43), nonce,
                AAD.empty());
        byte[] tampered = encrypted.ciphertext();
        tampered[10] ^= 0x40;

        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, tampered, encrypted.tag(), AAD.empty()));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
    }

    @Test
    void wrongNonceLengthIsRejected() {
        AeadCipher gcm = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        SecretKey key = TestSupport.aesKey(16, 51);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> gcm.encrypt(key, new byte[1], Nonce.of(new byte[8]), AAD.empty()));
        assertEquals(ErrorCode.NONCE_INVALID, exception.errorCode());

        CryptoException decryptException = assertThrows(CryptoException.class,
                () -> gcm.decrypt(key, Nonce.of(new byte[16]), new byte[1], new byte[16],
                        AAD.empty()));
        assertEquals(ErrorCode.NONCE_INVALID, decryptException.errorCode());
    }

    @Test
    void chacha20Poly1305RoundtripAndTamperDetection() {
        SecretKey key = TestSupport.chaChaKey(61);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.CHACHA20_POLY1305);
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 62));
        byte[] plaintext = TestSupport.bytes(777, 63);
        AAD aad = AAD.ofUtf8("chacha-aad");
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
        assertArrayEquals(plaintext, cipher.decrypt(key, nonce, encrypted.ciphertext(),
                encrypted.tag(), aad));

        byte[] tampered = encrypted.ciphertext();
        tampered[tampered.length - 1] ^= 0x01;
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, tampered, encrypted.tag(), aad));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
    }

    @Test
    void encryptThenMacBlockModesRoundtrip() {
        SecretKey key = TestSupport.aesKey(32, 71);
        byte[] plaintext = TestSupport.bytes(513, 72);
        AAD aad = AAD.ofUtf8("etm-aad");
        Nonce nonce = Nonce.of(TestSupport.bytes(16, 73));
        for (AlgorithmId algorithm : Set.of(AlgorithmId.AES_CBC, AlgorithmId.AES_CTR,
                AlgorithmId.AES_CFB, AlgorithmId.AES_OFB)) {
            AeadCipher cipher = PROVIDER.aeadCipher(algorithm);
            AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
            assertEquals(32, encrypted.tag().length);
            assertArrayEquals(plaintext, cipher.decrypt(key, nonce, encrypted.ciphertext(),
                    encrypted.tag(), aad), "roundtrip failed for " + algorithm);
        }
    }

    @Test
    void encryptThenMacDetectsCiphertextTagAndAadTampering() {
        SecretKey key = TestSupport.aesKey(16, 81);
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_CBC);
        Nonce nonce = Nonce.of(TestSupport.bytes(16, 82));
        AAD aad = AAD.ofUtf8("etm");
        AeadCipher.AeadResult encrypted = cipher.encrypt(key, TestSupport.bytes(80, 83), nonce, aad);

        byte[] tamperedCiphertext = encrypted.ciphertext();
        tamperedCiphertext[0] ^= 0x01;
        CryptoException ciphertextFailure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, tamperedCiphertext, encrypted.tag(), aad));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, ciphertextFailure.errorCode());

        byte[] tamperedTag = encrypted.tag();
        tamperedTag[31] ^= 0x01;
        CryptoException tagFailure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, encrypted.ciphertext(), tamperedTag, aad));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, tagFailure.errorCode());

        CryptoException aadFailure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, encrypted.ciphertext(), encrypted.tag(),
                        AAD.ofUtf8("other")));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, aadFailure.errorCode());
    }

    @Test
    void encryptThenMacRequiresSixteenByteNonce() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_CTR);
        SecretKey key = TestSupport.aesKey(16, 91);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.encrypt(key, new byte[1], Nonce.of(new byte[12]), AAD.empty()));
        assertEquals(ErrorCode.NONCE_INVALID, exception.errorCode());
    }

    @Test
    void encryptThenMacRejectsWrongTagLengthGenerically() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_CBC);
        SecretKey key = TestSupport.aesKey(16, 92);
        Nonce nonce = Nonce.of(TestSupport.bytes(16, 93));
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, new byte[16], new byte[8], AAD.empty()));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
    }

    @Test
    void aesGcmRejectsWrongTagLength() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        SecretKey key = TestSupport.aesKey(16, 94);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, Nonce.of(new byte[12]), new byte[1], new byte[8],
                        AAD.empty()));
        assertEquals(ErrorCode.TAG_INVALID, exception.errorCode());
    }

    @Test
    void authenticationFailureMessageNeverLeaksDetails() {
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.CHACHA20_POLY1305);
        SecretKey key = TestSupport.chaChaKey(95);
        Nonce nonce = Nonce.of(TestSupport.bytes(12, 96));
        AeadCipher.AeadResult encrypted = cipher.encrypt(key,
                "very-secret-plaintext".getBytes(StandardCharsets.UTF_8), nonce, AAD.empty());
        byte[] tag = encrypted.tag();
        tag[0] ^= 0x7f;
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(key, nonce, encrypted.ciphertext(), tag, AAD.empty()));
        assertEquals("Cryptographic authentication failed", exception.getMessage());
        assertFalse(exception.getMessage().contains("secret"));
    }
}
