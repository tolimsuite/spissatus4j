package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.algorithm.BcAlgorithmMapper;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import org.junit.jupiter.api.Test;

class BcAlgorithmMapperTest {

    private static final BcAlgorithmMapper MAPPER = new BcAlgorithmMapper();

    @Test
    void standardMappingsAreBidirectional() {
        assertEquals("AES/GCM/NoPadding", MAPPER.jcaName(AlgorithmId.AES_GCM));
        assertEquals("ChaCha20-Poly1305", MAPPER.jcaName(AlgorithmId.CHACHA20_POLY1305));
        assertEquals("Ed448", MAPPER.jcaName(AlgorithmId.ED448));
        assertEquals("SHA256withECDSAinP1363Format", MAPPER.jcaName(AlgorithmId.ECDSA_P256));
        assertEquals("SHA384withECDSAinP1363Format", MAPPER.jcaName(AlgorithmId.ECDSA_P384));
        assertEquals("RSASSA-PSS", MAPPER.jcaName(AlgorithmId.RSA_PSS));
        assertEquals("SHA256withRSA", MAPPER.jcaName(AlgorithmId.RSA_PKCS1_SIGNATURE));
        assertEquals("RSA/ECB/OAEPPadding", MAPPER.jcaName(AlgorithmId.RSA_OAEP));
        assertEquals("ECIES", MAPPER.jcaName(AlgorithmId.ECIES));
        assertEquals("AESCMAC", MAPPER.jcaName(AlgorithmId.CMAC_AES));
        assertEquals("SHAKE128-256", MAPPER.jcaName(AlgorithmId.SHAKE_128));
        assertEquals("SHAKE256-512", MAPPER.jcaName(AlgorithmId.SHAKE_256));
        assertEquals("BLAKE2B-512", MAPPER.jcaName(AlgorithmId.BLAKE2B_512));

        assertEquals(AlgorithmId.AES_GCM, MAPPER.algorithm("aes/gcm/nopadding"));
        assertEquals(AlgorithmId.ED448, MAPPER.algorithm("ED448"));
        assertEquals(AlgorithmId.ECDSA_P256,
                MAPPER.algorithm("sha256withecdsainp1363format"));
        assertEquals(AlgorithmId.RSA_OAEP, MAPPER.algorithm("RSA/ECB/OAEPPadding"));
        assertEquals(AlgorithmId.ECIES, MAPPER.algorithm("ecies"));
        assertEquals(AlgorithmId.CMAC_AES, MAPPER.algorithm("aescmac"));
        assertEquals(AlgorithmId.RSA_PKCS1_SIGNATURE, MAPPER.algorithm("sha256withrsa"));
        assertEquals(AlgorithmId.SHAKE_256, MAPPER.algorithm("shake256-512"));
        assertEquals(AlgorithmId.ARGON2ID, MAPPER.algorithm("argon2id"));
        assertTrue(MAPPER.hasMapping(AlgorithmId.SHAKE_256));
        assertTrue(MAPPER.algorithms().contains(AlgorithmId.AES_GCM));
    }

    @Test
    void missingMappingsThrowInsteadOfDowngrading() {
        AlgorithmId unknown = AlgorithmId.of("CUSTOM-ALG");
        CryptoException byId = assertThrows(CryptoException.class, () -> MAPPER.jcaName(unknown));
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, byId.errorCode());
        assertTrue(byId.getMessage().contains("CUSTOM-ALG"));

        CryptoException byName = assertThrows(CryptoException.class,
                () -> MAPPER.algorithm("NoSuchTransformation"));
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, byName.errorCode());
        assertFalse(MAPPER.hasMapping(unknown));
    }

    @Test
    void conflictingMappingsAreRejected() {
        BcAlgorithmMapper mapper = new BcAlgorithmMapper();

        ConfigurationException sameAlgorithm = assertThrows(ConfigurationException.class,
                () -> mapper.register(AlgorithmId.ED448, "Ed25519"));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, sameAlgorithm.errorCode());

        ConfigurationException sameJcaName = assertThrows(ConfigurationException.class,
                () -> mapper.register(AlgorithmId.of("CUSTOM-HMAC"), "HmacSHA256"));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, sameJcaName.errorCode());
    }

    @Test
    void reRegisteringTheSamePairIsIdempotent() {
        BcAlgorithmMapper mapper = new BcAlgorithmMapper();

        mapper.register(AlgorithmId.ED448, "Ed448");
        mapper.register(AlgorithmId.ED448, "Ed448");

        assertEquals("Ed448", mapper.jcaName(AlgorithmId.ED448));
        assertEquals(AlgorithmId.ED448, mapper.algorithm("Ed448"));
    }

    @Test
    void customMappingsRoundTrip() {
        BcAlgorithmMapper mapper = new BcAlgorithmMapper();
        AlgorithmId custom = AlgorithmId.of("CUSTOM-HASH");

        mapper.register(custom, "CUSTOM-DIGEST");

        assertEquals("CUSTOM-DIGEST", mapper.jcaName(custom));
        assertEquals(custom, mapper.algorithm("custom-digest"));
        assertTrue(mapper.algorithms().contains(custom));
    }

    @Test
    void blankJcaNamesAreRejected() {
        BcAlgorithmMapper mapper = new BcAlgorithmMapper();

        ConfigurationException failure = assertThrows(ConfigurationException.class,
                () -> mapper.register(AlgorithmId.of("CUSTOM"), "   "));

        assertEquals(ErrorCode.CONFIGURATION_INVALID, failure.errorCode());
    }
}