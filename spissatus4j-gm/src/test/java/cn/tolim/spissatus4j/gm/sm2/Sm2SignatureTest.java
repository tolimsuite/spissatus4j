package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sm2SignatureTest {

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    private final Sm2Signature signature = new Sm2Signature();
    private final byte[] message = "SM2 signature message 签名".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void setUp() throws Exception {
        GmTestSupport.ensureBcProvider();
        keyPair = GmTestSupport.sm2KeyPair();
        otherKeyPair = GmTestSupport.sm2KeyPair();
    }

    @Test
    void algorithmIsSm2Signature() {
        assertEquals(AlgorithmId.SM2_SIGNATURE, signature.algorithm());
    }

    @Test
    void signAndVerifyRoundtrip() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), message);
        assertTrue(signature.verify(keyPair.getPublic(), message, encodedSignature));
    }

    @Test
    void emptyMessageRoundtrip() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), new byte[0]);
        assertTrue(signature.verify(keyPair.getPublic(), new byte[0], encodedSignature));
    }

    @Test
    void signaturesAreDerSequences() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), message);
        assertEquals(0x30, encodedSignature[0] & 0xff);
        assertEquals(encodedSignature.length - 2, encodedSignature[1] & 0xff);
    }

    @Test
    void tamperedMessageFailsVerification() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), message);
        byte[] tampered = message.clone();
        tampered[0] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), tampered, encodedSignature));
    }

    @Test
    void tamperedSignatureFailsVerification() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), message);
        byte[] tampered = encodedSignature.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(signature.verify(keyPair.getPublic(), message, tampered));
    }

    @Test
    void malformedSignatureBytesReturnFalse() {
        assertFalse(signature.verify(keyPair.getPublic(), message, new byte[] {0x01, 0x02}));
        assertFalse(signature.verify(keyPair.getPublic(), message, new byte[0]));
    }

    @Test
    void wrongPublicKeyFailsVerification() {
        byte[] encodedSignature = signature.sign(keyPair.getPrivate(), message);
        assertFalse(signature.verify(otherKeyPair.getPublic(), message, encodedSignature));
    }

    @Test
    void wrongCurveKeysAreRejected() throws Exception {
        KeyPair p256 = GmTestSupport.ecKeyPair("secp256r1");
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.sign(p256.getPrivate(), message));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.verify(p256.getPublic(), message, new byte[70]));
    }

    @Test
    void malformedKeysAreRejected() {
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
        CryptoException signFailure =
                org.junit.jupiter.api.Assertions.assertThrows(CryptoException.class,
                        () -> signature.sign(malformedPrivate, message));
        assertEquals(ErrorCode.INVALID_PARAMETER, signFailure.errorCode());
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.verify(malformedPublic, message, new byte[70]));
    }

    @Test
    void nullArgumentsAreRejected() {
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.sign(null, message));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.sign(keyPair.getPrivate(), (byte[]) null));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> signature.verify(keyPair.getPublic(), message, null));
    }

    @Test
    void interoperatesWithBcJcaSm3WithSm2() throws Exception {
        GmTestSupport.ensureBcProvider();

        Signature jcaSigner = Signature.getInstance("SM3withSM2", BouncyCastleProvider.PROVIDER_NAME);
        jcaSigner.initSign(keyPair.getPrivate());
        jcaSigner.update(message);
        byte[] jcaSignature = jcaSigner.sign();
        assertTrue(signature.verify(keyPair.getPublic(), message, jcaSignature));

        byte[] ourSignature = signature.sign(keyPair.getPrivate(), message);
        Signature jcaVerifier = Signature.getInstance("SM3withSM2", BouncyCastleProvider.PROVIDER_NAME);
        jcaVerifier.initVerify(keyPair.getPublic());
        jcaVerifier.update(message);
        assertTrue(jcaVerifier.verify(ourSignature));
    }

    @Test
    void signingIsRandomizedButAlwaysVerifies() {
        byte[] first = signature.sign(keyPair.getPrivate(), message);
        byte[] second = signature.sign(keyPair.getPrivate(), message);
        assertTrue(signature.verify(keyPair.getPublic(), message, first));
        assertTrue(signature.verify(keyPair.getPublic(), message, second));
        assertNotEquals(GmTestSupport.hex(first), GmTestSupport.hex(second));
    }
}