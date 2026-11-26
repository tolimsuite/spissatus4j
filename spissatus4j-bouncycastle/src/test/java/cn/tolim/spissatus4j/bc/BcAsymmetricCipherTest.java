package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class BcAsymmetricCipherTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER.jcaProvider());
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        otherKeyPair = generator.generateKeyPair();
    }

    @Test
    void rsaOaepRoundTrip() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] plaintext = "wrapped session key".getBytes(StandardCharsets.UTF_8);

        byte[] sealed = cipher.encrypt(keyPair.getPublic(), plaintext);

        assertEquals(AlgorithmId.RSA_OAEP, cipher.algorithm());
        assertEquals(256, sealed.length);
        assertFalse(Arrays.equals(plaintext, sealed));
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), sealed));
    }

    @Test
    void decryptionWithWrongKeyFailsClosed() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] sealed = cipher.encrypt(keyPair.getPublic(),
                "secret".getBytes(StandardCharsets.UTF_8));

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(otherKeyPair.getPrivate(), sealed));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void tamperedCiphertextFailsClosed() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] sealed = cipher.encrypt(keyPair.getPublic(),
                "secret".getBytes(StandardCharsets.UTF_8));
        sealed[sealed.length / 2] ^= 0x01;

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), sealed));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
    }

    @Test
    void ciphertextEqualToTheModulusFailsAsAuthenticationFailure() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), modulusBytes(keyPair)));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void oversizedAllOnesCiphertextFailsAsAuthenticationFailure() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] ciphertext = new byte[256];
        Arrays.fill(ciphertext, (byte) 0xFF);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), ciphertext));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void shortCiphertextFailsClosed() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.decrypt(keyPair.getPrivate(), new byte[32]));

        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void explicitSha256OaepInteroperatesWithSunJce() throws Exception {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);
        byte[] plaintext = "interoperable payload".getBytes(StandardCharsets.UTF_8);
        Cipher jdk = Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE");

        jdk.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), OAEP_SHA256);
        byte[] sealedByJdk = jdk.doFinal(plaintext);
        assertArrayEquals(plaintext, cipher.decrypt(keyPair.getPrivate(), sealedByJdk));

        byte[] sealedByBc = cipher.encrypt(keyPair.getPublic(), plaintext);
        jdk.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), OAEP_SHA256);
        assertArrayEquals(plaintext, jdk.doFinal(sealedByBc));
    }

    @Test
    void oversizedPlaintextIsRejected() {
        AsymmetricCipher cipher = PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> cipher.encrypt(keyPair.getPublic(), new byte[200]));

        assertEquals(ErrorCode.ENCRYPTION_FAILED, failure.errorCode());
    }

    private static byte[] modulusBytes(KeyPair pair) {
        BigInteger modulus = ((RSAPublicKey) pair.getPublic()).getModulus();
        int size = (modulus.bitLength() + 7) / 8;
        byte[] encoded = modulus.toByteArray();
        return encoded.length == size
                ? encoded
                : Arrays.copyOfRange(encoded, encoded.length - size, encoded.length);
    }
}