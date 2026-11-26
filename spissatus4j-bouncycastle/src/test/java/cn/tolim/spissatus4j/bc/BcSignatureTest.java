package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

class BcSignatureTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();
    private static final byte[] MESSAGE = "signed message".getBytes(StandardCharsets.UTF_8);

    @Test
    void ed448RoundTripAndTamperDetection() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed448",
                PROVIDER.jcaProvider());
        KeyPair keyPair = generator.generateKeyPair();
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ED448);

        byte[] signed = signature.sign(keyPair.getPrivate(), MESSAGE);

        assertEquals(114, signed.length);
        assertTrue(signature.verify(keyPair.getPublic(), MESSAGE, signed));
        assertFalse(signature.verify(keyPair.getPublic(),
                "other message".getBytes(StandardCharsets.UTF_8), signed));
        byte[] tampered = signed.clone();
        tampered[0] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), MESSAGE, tampered));
    }

    @Test
    void rsaPssRoundTripAndWrongKeyRejection() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER.jcaProvider());
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        KeyPair other = generator.generateKeyPair();
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.RSA_PSS);

        byte[] signed = signature.sign(keyPair.getPrivate(), MESSAGE);

        assertEquals(256, signed.length);
        assertTrue(signature.verify(keyPair.getPublic(), MESSAGE, signed));
        assertFalse(signature.verify(keyPair.getPublic(),
                "tampered".getBytes(StandardCharsets.UTF_8), signed));
        assertFalse(signature.verify(other.getPublic(), MESSAGE, signed));
    }

    @Test
    void rsaPkcs1V15SignatureRoundTripAndRejections() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER.jcaProvider());
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        KeyPair other = generator.generateKeyPair();
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.RSA_PKCS1_SIGNATURE);

        byte[] signed = signature.sign(keyPair.getPrivate(), MESSAGE);

        assertEquals(AlgorithmId.RSA_PKCS1_SIGNATURE, signature.algorithm());
        assertEquals(256, signed.length);
        assertTrue(signature.verify(keyPair.getPublic(), MESSAGE, signed));
        assertFalse(signature.verify(keyPair.getPublic(),
                "tampered".getBytes(StandardCharsets.UTF_8), signed));
        assertFalse(signature.verify(other.getPublic(), MESSAGE, signed));
        byte[] tampered = signed.clone();
        tampered[0] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), MESSAGE, tampered));
    }

    @Test
    void rsaKeysBelow2048BitsAreRejected() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER.jcaProvider());
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.RSA_PSS);
        CryptoException failure = assertThrows(CryptoException.class,
                () -> signature.sign(keyPair.getPrivate(), MESSAGE));
        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, failure.errorCode());
        CryptoException verifyFailure = assertThrows(CryptoException.class,
                () -> signature.verify(keyPair.getPublic(), MESSAGE, new byte[128]));
        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, verifyFailure.errorCode());
    }

    @Test
    void ecdsaP256UsesP1363Encoding() throws Exception {
        KeyPair keyPair = ecdsaKeyPair("secp256r1");
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ECDSA_P256);

        byte[] signed = signature.sign(keyPair.getPrivate(), MESSAGE);

        assertEquals(64, signed.length, "P-256 P1363 signatures are 64 bytes");
        assertTrue(signature.verify(keyPair.getPublic(), MESSAGE, signed));
        assertFalse(signature.verify(keyPair.getPublic(),
                "tampered".getBytes(StandardCharsets.UTF_8), signed));
    }

    @Test
    void ecdsaP384UsesP1363Encoding() throws Exception {
        KeyPair keyPair = ecdsaKeyPair("secp384r1");
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ECDSA_P384);

        byte[] signed = signature.sign(keyPair.getPrivate(), MESSAGE);

        assertEquals(96, signed.length, "P-384 P1363 signatures are 96 bytes");
        assertTrue(signature.verify(keyPair.getPublic(), MESSAGE, signed));
    }

    @Test
    void malformedSignatureReturnsFalse() throws Exception {
        KeyPair keyPair = ecdsaKeyPair("secp256r1");
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ECDSA_P256);

        assertFalse(signature.verify(keyPair.getPublic(), MESSAGE, new byte[64]));
        assertFalse(signature.verify(keyPair.getPublic(), MESSAGE, new byte[]{1, 2, 3}));
    }

    @Test
    void invalidPrivateKeyIsRejectedWithoutSecrets() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed448",
                PROVIDER.jcaProvider());
        var wrongTypeKey = generator.generateKeyPair().getPrivate();
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ECDSA_P256);

        CryptoException failure = assertThrows(CryptoException.class,
                () -> signature.sign(wrongTypeKey, MESSAGE));

        assertEquals(ErrorCode.INVALID_PARAMETER, failure.errorCode());
        assertEquals("Invalid private key for signature", failure.getMessage());
    }

    private static KeyPair ecdsaKeyPair(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", PROVIDER.jcaProvider());
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }
}