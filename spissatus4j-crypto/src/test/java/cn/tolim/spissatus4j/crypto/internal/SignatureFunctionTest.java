package cn.tolim.spissatus4j.crypto.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.crypto.TestSupport;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SignatureFunctionTest {

    private static final JcaAlgorithmProvider PROVIDER = new JcaAlgorithmProvider();
    private static KeyPair ed25519;
    private static KeyPair ed448;
    private static KeyPair p256;
    private static KeyPair p384;
    private static KeyPair rsa;

    @BeforeAll
    static void generateKeys() {
        ed25519 = TestSupport.edKeyPair("Ed25519");
        ed448 = TestSupport.edKeyPair("Ed448");
        p256 = TestSupport.ecKeyPair("secp256r1");
        p384 = TestSupport.ecKeyPair("secp384r1");
        rsa = TestSupport.rsaKeyPair(2048);
    }

    @Test
    void ed25519SignAndVerify() {
        assertSignVerify(AlgorithmId.ED25519, ed25519, 64);
    }

    @Test
    void ed448SignAndVerify() {
        assertSignVerify(AlgorithmId.ED448, ed448, 114);
    }

    @Test
    void ecdsaP256UsesP1363Encoding() {
        assertSignVerify(AlgorithmId.ECDSA_P256, p256, 64);
    }

    @Test
    void ecdsaP384UsesP1363Encoding() {
        assertSignVerify(AlgorithmId.ECDSA_P384, p384, 96);
    }

    @Test
    void rsaPssSignAndVerify() {
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.RSA_PSS);
        byte[] message = "rsa-pss message".getBytes(StandardCharsets.UTF_8);
        byte[] signed = signature.sign(rsa.getPrivate(), message);
        assertTrue(signature.verify(rsa.getPublic(), message, signed));
        byte[] tamperedMessage = message.clone();
        tamperedMessage[0] ^= 0x01;
        assertFalse(signature.verify(rsa.getPublic(), tamperedMessage, signed));
    }

    @Test
    void verifyRejectsMalformedSignatureWithoutThrowing() {
        SignatureFunction signature = PROVIDER.signature(AlgorithmId.ED25519);
        assertFalse(signature.verify(ed25519.getPublic(), new byte[]{1, 2, 3}, new byte[10]));
    }

    private static void assertSignVerify(AlgorithmId algorithm, KeyPair keyPair, int signatureLength) {
        SignatureFunction signature = PROVIDER.signature(algorithm);
        byte[] message = ("message for " + algorithm.id()).getBytes(StandardCharsets.UTF_8);
        byte[] signed = signature.sign(keyPair.getPrivate(), message);
        assertEquals(signatureLength, signed.length);
        assertTrue(signature.verify(keyPair.getPublic(), message, signed));
        byte[] tampered = message.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), tampered, signed));
        byte[] tamperedSignature = signed.clone();
        tamperedSignature[tamperedSignature.length / 2] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), message, tamperedSignature));
    }
}
