package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.internal.Sm2Operations;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Sm2CipherTest {

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    private final Sm2Cipher cipher = new Sm2Cipher();

    @BeforeAll
    static void setUp() throws Exception {
        GmTestSupport.ensureBcProvider();
        keyPair = GmTestSupport.sm2KeyPair();
        otherKeyPair = GmTestSupport.sm2KeyPair();
    }

    @Test
    void algorithmIsSm2() {
        assertEquals(AlgorithmId.SM2, cipher.algorithm());
    }

    @Test
    void encryptDecryptRoundtrip() {
        byte[] plaintext = "SM2 encryption payload 你好".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), plaintext);
        assertEquals(plaintext.length + Sm2Operations.MIN_CIPHERTEXT_LENGTH, ciphertext.length);
        assertEquals(0x04, ciphertext[0] & 0xff);
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), ciphertext));
    }

    @Test
    void emptyPlaintextIsRejectedByLengthBounds() {
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(keyPair.getPublic(), new byte[0]));
    }

    @Test
    void oneBytePlaintextRoundtrip() {
        byte[] plaintext = new byte[] {0x42};
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), plaintext);
        assertEquals(Sm2Operations.MIN_CIPHERTEXT_LENGTH + 1, ciphertext.length);
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), ciphertext));
    }

    @Test
    void randomizedEncryptionProducesDifferentCiphertexts() {
        byte[] plaintext = "same plaintext".getBytes(StandardCharsets.US_ASCII);
        byte[] first = cipher.encrypt(keyPair.getPublic(), plaintext);
        byte[] second = cipher.encrypt(keyPair.getPublic(), plaintext);
        assertEquals(false, java.util.Arrays.equals(first, second));
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), first));
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), second));
    }

    @Test
    void tamperedCiphertextFailsGenerically() {
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), "secret".getBytes(StandardCharsets.US_ASCII));
        byte[] tampered = ciphertext.clone();
        tampered[tampered.length - 1] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(() -> cipher.decrypt(keyPair.getPrivate(), tampered));
    }

    @Test
    void tamperedC1FailsGenerically() {
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), "secret".getBytes(StandardCharsets.US_ASCII));
        byte[] tampered = ciphertext.clone();
        tampered[10] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(() -> cipher.decrypt(keyPair.getPrivate(), tampered));
    }

    @Test
    void wrongPrivateKeyFailsGenerically() {
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), "secret".getBytes(StandardCharsets.US_ASCII));
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(otherKeyPair.getPrivate(), ciphertext));
    }

    @Test
    void truncatedCiphertextFailsGenerically() {
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(keyPair.getPrivate(), new byte[16]));
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(keyPair.getPrivate(), new byte[Sm2Operations.MIN_CIPHERTEXT_LENGTH - 1]));
    }

    @Test
    void wrongCurveKeysAreRejected() throws Exception {
        KeyPair p256 = GmTestSupport.ecKeyPair("secp256r1");
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(p256.getPublic(), new byte[8]));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.decrypt(p256.getPrivate(), new byte[Sm2Operations.MIN_CIPHERTEXT_LENGTH]));
    }

    @Test
    void malformedKeysAreRejected() {
        PublicKey malformedPublic = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "EC";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[] {0x01, 0x02, 0x03};
            }
        };
        PrivateKey malformedPrivate = new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "EC";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[] {0x01, 0x02, 0x03};
            }
        };
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(malformedPublic, new byte[8]));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.decrypt(malformedPrivate, new byte[100]));
    }

    @Test
    void oversizedPlaintextIsRejected() {
        byte[] tooLarge = new byte[Sm2Operations.MAX_PLAINTEXT_LENGTH + 1];
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(keyPair.getPublic(), tooLarge));
    }

    @Test
    void nullArgumentsAreRejected() {
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(null, new byte[1]));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(keyPair.getPublic(), null));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.decrypt(keyPair.getPrivate(), null));
    }

    @Test
    void ciphertextContainsNoPlaintext() {
        byte[] plaintext = "UNIQUE-MARKER-PLAINTEXT".getBytes(StandardCharsets.US_ASCII);
        byte[] ciphertext = cipher.encrypt(keyPair.getPublic(), plaintext);
        String encodedCiphertext = GmTestSupport.hex(ciphertext);
        assertFalse(encodedCiphertext.contains(GmTestSupport.hex(plaintext)));
    }
}