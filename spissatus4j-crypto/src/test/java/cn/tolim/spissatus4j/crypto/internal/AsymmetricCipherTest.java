package cn.tolim.spissatus4j.crypto.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.crypto.TestSupport;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AsymmetricCipherTest {

    private static final JcaAlgorithmProvider PROVIDER = new JcaAlgorithmProvider();
    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void generateKeys() {
        rsaKeyPair = TestSupport.rsaKeyPair(2048);
    }

    @Test
    void rsaOaepRoundtrip() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] plaintext = TestSupport.bytes(190, 1);
        byte[] encrypted = cipher.encrypt(rsaKeyPair.getPublic(), plaintext);
        assertEquals(256, encrypted.length);
        assertArrayEquals(plaintext, cipher.decrypt(rsaKeyPair.getPrivate(), encrypted));
    }

    @Test
    void rsaPkcs1Roundtrip() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_PKCS1);
        byte[] plaintext = TestSupport.bytes(100, 2);
        byte[] encrypted = cipher.encrypt(rsaKeyPair.getPublic(), plaintext);
        assertArrayEquals(plaintext, cipher.decrypt(rsaKeyPair.getPrivate(), encrypted));
    }

    @Test
    void rsaOaepDetectsCiphertextTamper() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] encrypted = cipher.encrypt(rsaKeyPair.getPublic(), TestSupport.bytes(32, 3));
        encrypted[10] ^= 0x01;
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.decrypt(rsaKeyPair.getPrivate(), encrypted));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
    }

    @Test
    void rsaKeysBelow2048BitsAreRejected() {
        KeyPair small = TestSupport.rsaKeyPair(1024);
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> cipher.encrypt(small.getPublic(), new byte[16]));
        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, exception.errorCode());
    }
}
