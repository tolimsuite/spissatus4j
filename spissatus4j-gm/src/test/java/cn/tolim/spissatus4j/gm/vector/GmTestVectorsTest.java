package cn.tolim.spissatus4j.gm.vector;

import cn.tolim.spissatus4j.gm.internal.Sm4Ecb;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.security.KeyPair;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GmTestVectorsTest {

    @Test
    void allPublishedVectorsVerify() {
        assertTrue(GmTestVectors.verifySm3Abc());
        assertTrue(GmTestVectors.verifySm4EcbVector());
        assertTrue(GmTestVectors.verifySm4GcmRoundtrip());
        assertTrue(GmTestVectors.verifySm2Roundtrip());
    }

    @Test
    void internalSm4EcbHelperMatchesKnownAnswer() {
        byte[] encrypted = Sm4Ecb.encryptBlock(
                GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_KEY),
                GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_PLAINTEXT));
        assertArrayEquals(GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_CIPHERTEXT), encrypted);
        assertEquals("681edf34d206965e86b3e94f536e4246", GmTestSupport.hex(encrypted));
    }

    @Test
    void vectorConstantsAreWellFormed() {
        assertEquals(32, GmTestVectors.hexToBytes(GmTestVectors.SM3_ABC_DIGEST).length);
        assertEquals(32, GmTestVectors.hexToBytes(GmTestVectors.SM3_ABCD_X16_DIGEST).length);
        assertEquals(16, GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_KEY).length);
        assertEquals(16, GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_PLAINTEXT).length);
        assertEquals(16, GmTestVectors.hexToBytes(GmTestVectors.SM4_ECB_CIPHERTEXT).length);
        assertEquals(12, GmTestVectors.hexToBytes(GmTestVectors.SM4_GCM_NONCE).length);
        assertEquals(64, GmTestVectors.SM3_ABCD_X16_INPUT.length());
        assertEquals("abcd".repeat(16), GmTestVectors.SM3_ABCD_X16_INPUT);
        assertEquals("abc", GmTestVectors.SM3_ABC_INPUT);
        assertEquals(GmTestVectors.SM4_ECB_KEY, GmTestVectors.SM4_ECB_PLAINTEXT);
        assertEquals(GmTestVectors.SM4_ECB_KEY, GmTestVectors.SM4_VECTOR_KEY);
    }

    @Test
    void vectorChecksAreRepeatable() {
        for (int i = 0; i < 3; i++) {
            assertTrue(GmTestVectors.verifySm3Abc());
            assertTrue(GmTestVectors.verifySm4EcbVector());
            assertTrue(GmTestVectors.verifySm4GcmRoundtrip());
            assertTrue(GmTestVectors.verifySm2Roundtrip());
        }
    }

    @Test
    void jcaKeyRoundtripHelperAcceptsGeneratedSm2Keys() throws Exception {
        KeyPair keyPair = GmTestSupport.sm2KeyPair();
        assertTrue(GmTestVectors.verifyJcaKeyRoundtrip(keyPair));
        assertEquals(32, HexFormat.of().parseHex(
                GmTestVectors.SM3_ABC_DIGEST).length);
    }
}