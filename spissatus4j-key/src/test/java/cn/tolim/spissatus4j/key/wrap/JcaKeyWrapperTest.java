package cn.tolim.spissatus4j.key.wrap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class JcaKeyWrapperTest {

    @Test
    void defaultWrapperSupportsAllDocumentedAlgorithms() throws Exception {
        JcaKeyWrapper wrapper = new JcaKeyWrapper();
        assertEquals("jca-default", wrapper.wrapperId());
        assertEquals(Set.of(AlgorithmId.AES_KW, AlgorithmId.RSA_OAEP, AlgorithmId.RSA_PKCS1),
                wrapper.algorithms());
        assertEquals(HealthStatus.UP, wrapper.health());

        byte[] dek = material(32, 0x01);
        SecretKey kek = aesKey();
        byte[] wrapped = wrapper.wrap(kek, dek);
        assertEquals(40, wrapped.length);
        assertArrayEquals(dek, wrapper.unwrap(kek, wrapped));

        KeyPair pair = rsaKeyPair();
        byte[] rsaWrapped = wrapper.wrap(pair.getPublic(), dek);
        assertEquals(256, rsaWrapped.length);
        assertArrayEquals(dek, wrapper.unwrap(pair.getPrivate(), rsaWrapped));

        byte[] tampered = wrapped.clone();
        tampered[tampered.length - 1] ^= 0x01;
        CryptoException failure = assertThrows(CryptoException.class,
                () -> wrapper.unwrap(kek, tampered));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertEquals("Cryptographic authentication failed", failure.getMessage());
    }

    @Test
    void wrapsAndUnwrapsWithRsaOaep() throws Exception {
        JcaKeyWrapper wrapper = new JcaKeyWrapper(AlgorithmId.RSA_OAEP);
        KeyPair pair = rsaKeyPair();
        byte[] dek = material(32, 0x11);
        byte[] wrapped = wrapper.wrap(pair.getPublic(), dek);
        assertEquals(256, wrapped.length);
        assertArrayEquals(dek, wrapper.unwrap(pair.getPrivate(), wrapped));

        KeyPair other = rsaKeyPair();
        CryptoException failure = assertThrows(CryptoException.class,
                () -> wrapper.unwrap(other.getPrivate(), wrapped));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());

        byte[] tampered = wrapped.clone();
        tampered[0] ^= 0x01;
        assertEquals(ErrorCode.AUTHENTICATION_FAILED,
                assertThrows(CryptoException.class,
                        () -> wrapper.unwrap(pair.getPrivate(), tampered)).errorCode());
        assertEquals(HealthStatus.UP, wrapper.health());
    }

    @Test
    void wrapsAndUnwrapsWithRsaPkcs1() throws Exception {
        JcaKeyWrapper wrapper = new JcaKeyWrapper(AlgorithmId.RSA_PKCS1);
        KeyPair pair = rsaKeyPair();
        byte[] dek = material(32, 0x21);
        byte[] wrapped = wrapper.wrap(pair.getPublic(), dek);
        assertEquals(256, wrapped.length);
        assertArrayEquals(dek, wrapper.unwrap(pair.getPrivate(), wrapped));
        assertEquals(HealthStatus.UP, wrapper.health());
    }

    @Test
    void rejectsUnsupportedMaterialKinds() throws Exception {
        JcaKeyWrapper aes = new JcaKeyWrapper(AlgorithmId.AES_KW);
        CryptoException asymmetric = assertThrows(CryptoException.class,
                () -> aes.wrap(rsaKeyPair().getPublic(), material(32, 0x31)));
        assertEquals(ErrorCode.UNSUPPORTED_OPERATION, asymmetric.errorCode());

        JcaKeyWrapper rsa = new JcaKeyWrapper(AlgorithmId.RSA_OAEP);
        CryptoException symmetric = assertThrows(CryptoException.class,
                () -> rsa.wrap(aesKey(), material(32, 0x32)));
        assertEquals(ErrorCode.UNSUPPORTED_OPERATION, symmetric.errorCode());

        assertThrows(IllegalArgumentException.class,
                () -> new JcaKeyWrapper(AlgorithmId.AES_GCM));
        List<KeyWrapper> defaults = JcaKeyWrapper.defaults();
        assertEquals(3, defaults.size());
        assertTrue(defaults.stream().anyMatch(wrapper -> wrapper.supports(AlgorithmId.AES_KW)));
        assertTrue(defaults.stream().anyMatch(wrapper -> wrapper.supports(AlgorithmId.RSA_OAEP)));
        assertTrue(defaults.stream().anyMatch(wrapper -> wrapper.supports(AlgorithmId.RSA_PKCS1)));
    }

    private static SecretKey aesKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            return generator.generateKey();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte[] material(int length, int seed) {
        byte[] material = new byte[length];
        for (int i = 0; i < length; i++) {
            material[i] = (byte) (seed + i);
        }
        return material;
    }
}