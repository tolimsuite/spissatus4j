package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sm2KeyWrapperTest {

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    private final Sm2KeyWrapper wrapper = new Sm2KeyWrapper();
    private final byte[] dek = GmTestSupport.HMAC_KEY.clone();

    @BeforeAll
    static void setUp() throws Exception {
        GmTestSupport.ensureBcProvider();
        keyPair = GmTestSupport.sm2KeyPair();
        otherKeyPair = GmTestSupport.sm2KeyPair();
    }

    @Test
    void metadata() {
        assertEquals("sm2", wrapper.wrapperId());
        assertEquals(Set.of(AlgorithmId.SM2), wrapper.algorithms());
        assertTrue(wrapper.supports(AlgorithmId.SM2));
        assertEquals(false, wrapper.supports(AlgorithmId.SM4_GCM));
        assertEquals(HealthStatus.UP, wrapper.health());
    }

    @Test
    void wrapUnwrapRoundtrip() {
        byte[] wrapped = wrapper.wrap(keyPair.getPublic(), dek);
        assertArrayEquals(dek, wrapper.unwrap(keyPair.getPrivate(), wrapped));
    }

    @Test
    void wrappingIsRandomized() {
        byte[] first = wrapper.wrap(keyPair.getPublic(), dek);
        byte[] second = wrapper.wrap(keyPair.getPublic(), dek);
        assertEquals(false, Arrays.equals(first, second));
        assertArrayEquals(dek, wrapper.unwrap(keyPair.getPrivate(), first));
        assertArrayEquals(dek, wrapper.unwrap(keyPair.getPrivate(), second));
    }

    @Test
    void unwrapWithWrongKekFailsGenerically() {
        byte[] wrapped = wrapper.wrap(keyPair.getPublic(), dek);
        GmTestSupport.assertAuthenticationFailure(
                () -> wrapper.unwrap(otherKeyPair.getPrivate(), wrapped));
    }

    @Test
    void unwrapTamperedDekFailsGenerically() {
        byte[] wrapped = wrapper.wrap(keyPair.getPublic(), dek);
        wrapped[wrapped.length - 1] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> wrapper.unwrap(keyPair.getPrivate(), wrapped));
    }

    @Test
    void wrapWithWrongCurveKeyIsRejected() throws Exception {
        KeyPair p256 = GmTestSupport.ecKeyPair("secp256r1");
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> wrapper.wrap(p256.getPublic(), dek));
    }

    @Test
    void symmetricWrappingIsNotSupported() {
        CryptoException exception = assertThrows(CryptoException.class,
                () -> wrapper.wrap(GmTestSupport.sm4Key(), dek));
        assertEquals(ErrorCode.UNSUPPORTED_OPERATION, exception.errorCode());
    }
}