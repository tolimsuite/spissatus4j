package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class BcEciesTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final byte[] MESSAGE = "ecies payload".getBytes(StandardCharsets.UTF_8);
    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", PROVIDER.jcaProvider());
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = generator.generateKeyPair();
        otherKeyPair = generator.generateKeyPair();
    }

    @Test
    void eciesRoundTripIncludesEphemeralKey() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.ECIES);

        byte[] sealed = cipher.encrypt(keyPair.getPublic(), MESSAGE);
        byte[] sealedAgain = cipher.encrypt(keyPair.getPublic(), MESSAGE);

        assertEquals(AlgorithmId.ECIES, cipher.algorithm());
        assertTrue(sealed.length > MESSAGE.length,
                "the ephemeral public key and authentication tag must be present");
        assertFalse(Arrays.equals(MESSAGE, sealed));
        assertFalse(Arrays.equals(sealed, sealedAgain),
                "fresh ephemeral keys must randomise the ciphertext");
        assertArrayEquals(MESSAGE, cipher.decrypt(keyPair.getPrivate(), sealed));
        assertArrayEquals(MESSAGE, cipher.decrypt(keyPair.getPrivate(), sealedAgain));
    }

    @Test
    void wrongKeyFailsWithGenericAuthenticationFailure() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.ECIES);
        byte[] sealed = cipher.encrypt(keyPair.getPublic(), MESSAGE);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(otherKeyPair.getPrivate(), sealed));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void tamperedCiphertextFailsWithGenericAuthenticationFailure() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.ECIES);
        byte[] sealed = cipher.encrypt(keyPair.getPublic(), MESSAGE);
        sealed[sealed.length / 2] ^= 0x01;

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), sealed));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void shortCiphertextFailsWithGenericAuthenticationFailure() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.ECIES);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), new byte[5]));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void invalidKeyTypeFailsClosed() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER.jcaProvider());
        generator.initialize(2048);
        KeyPair rsaKeyPair = generator.generateKeyPair();
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.ECIES);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.encrypt(rsaKeyPair.getPublic(), MESSAGE));

        assertEquals(ErrorCode.INVALID_PARAMETER, failure.errorCode());
    }
}