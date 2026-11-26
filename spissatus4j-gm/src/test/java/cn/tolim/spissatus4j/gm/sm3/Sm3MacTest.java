package cn.tolim.spissatus4j.gm.sm3;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sm3MacTest {

    private final Sm3Mac mac = new Sm3Mac();
    private final SecretKey key = GmTestSupport.hmacKey();
    private final byte[] data = "message to authenticate 消息".getBytes(StandardCharsets.UTF_8);

    @Test
    void algorithmAndTagLength() {
        assertEquals(AlgorithmId.HMAC_SM3, mac.algorithm());
        assertEquals(32, mac.tagLength());
        assertEquals(32, mac.compute(key, data).length);
    }

    @Test
    void computeIsStableAndVerifies() {
        byte[] first = mac.compute(key, data);
        byte[] second = mac.compute(key, data);
        assertArrayEquals(first, second);
        assertTrue(mac.verify(key, data, first));
    }

    @Test
    void tamperedTagIsRejected() {
        byte[] tag = mac.compute(key, data);
        tag[0] ^= 0x01;
        assertFalse(mac.verify(key, data, tag));
    }

    @Test
    void tamperedDataIsRejected() {
        byte[] tag = mac.compute(key, data);
        byte[] changed = data.clone();
        changed[changed.length - 1] ^= 0x01;
        assertFalse(mac.verify(key, changed, tag));
    }

    @Test
    void wrongLengthTagIsRejected() {
        assertFalse(mac.verify(key, data, new byte[16]));
        assertFalse(mac.verify(key, data, null));
    }

    @Test
    void streamMacMatchesArrayMac() throws IOException {
        byte[] expected = mac.compute(key, data);
        byte[] streamed = mac.compute(key, new ByteArrayInputStream(data));
        assertArrayEquals(expected, streamed);
    }

    @Test
    void crossCheckWithBcJcaHmacSm3() throws GeneralSecurityException {
        GmTestSupport.ensureBcProvider();
        Mac jcaMac = Mac.getInstance("HmacSM3", BouncyCastleProvider.PROVIDER_NAME);
        jcaMac.init(key);
        byte[] expected = jcaMac.doFinal(data);
        assertArrayEquals(expected, mac.compute(key, data));
    }

    @Test
    void differentKeysProduceDifferentTags() {
        SecretKey other = GmTestSupport.secretKey(new byte[32], "HmacSM3");
        assertNotEquals(GmTestSupport.hex(mac.compute(key, data)),
                GmTestSupport.hex(mac.compute(other, data)));
    }

    @Test
    void keyWithoutEncodingIsRejected() {
        SecretKey withoutEncoding = new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "HmacSM3";
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }
        };
        CryptoException exception =
                assertThrows(CryptoException.class, () -> mac.compute(withoutEncoding, data));
        assertEquals(ErrorCode.INVALID_PARAMETER, exception.errorCode());
    }

    @Test
    void nullInputsAreRejected() {
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER, () -> mac.compute(null, data));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER, () -> mac.compute(key, (byte[]) null));
    }
}