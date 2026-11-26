package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.SecurityStatus;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AlgorithmCatalogTest {

    @Test
    void catalogContainsCoreAlgorithms() {
        assertFalse(AlgorithmCatalog.all().isEmpty());
        assertTrue(AlgorithmCatalog.lookup("AES-GCM").isPresent());
        assertTrue(AlgorithmCatalog.lookup("aes-gcm").isPresent());
        assertEquals(AlgorithmFamily.AEAD, AlgorithmId.AES_GCM.family());
        assertEquals(SecurityStatus.RECOMMENDED, AlgorithmId.AES_GCM.status());
        assertEquals(12, AlgorithmId.AES_GCM.info().nonceBytes());
        assertEquals(16, AlgorithmId.AES_GCM.info().tagBytes());
        assertTrue(AlgorithmId.AES_GCM.info().fipsApproved());
        assertTrue(AlgorithmId.SM4_GCM.info().gm());
        assertTrue(AlgorithmId.ML_KEM_768.info().postQuantum());
    }

    @Test
    void securityPostureMatchesDefaults() {
        assertEquals(SecurityStatus.PROHIBITED, AlgorithmId.MD5.status());
        assertEquals(SecurityStatus.PROHIBITED, AlgorithmId.SHA_1.status());
        assertEquals(SecurityStatus.PROHIBITED, AlgorithmId.AES_ECB.status());
        assertEquals(SecurityStatus.PROHIBITED, AlgorithmId.RC4.status());
        assertEquals(SecurityStatus.DEPRECATED, AlgorithmId.DES_EDE3_CBC.status());
        assertEquals(SecurityStatus.DEPRECATED, AlgorithmId.RSA_PKCS1_SIGNATURE.status());
        assertEquals(SecurityStatus.EXPERIMENTAL, AlgorithmId.ML_DSA_65.status());
        assertTrue(AlgorithmId.SHA_256.info().supportsUsage(KeyUsage.ENCRYPT)
                || AlgorithmId.SHA_256.info().usages().isEmpty());
        assertTrue(AlgorithmId.AES_GCM.info().supportsUsage(KeyUsage.ENCRYPT));
        assertTrue(AlgorithmId.AES_KW.info().supportsUsage(KeyUsage.WRAP));
    }

    @Test
    void unknownAlgorithmHasUnknownInfo() {
        AlgorithmId id = AlgorithmId.of("NOT-A-REAL-ALGORITHM");
        assertFalse(id.isKnown());
        assertEquals(AlgorithmFamily.UNKNOWN, id.family());
        assertEquals(SecurityStatus.UNKNOWN, id.status());
        assertTrue(id.info().prohibited());
    }

    @Test
    void identitiesAreNormalized() {
        assertEquals(AlgorithmId.AES_GCM, AlgorithmId.of("AES-GCM"));
        assertEquals(AlgorithmId.AES_GCM.hashCode(), AlgorithmId.of("aes-gcm").hashCode());
        assertThrows(IllegalArgumentException.class, () -> AlgorithmId.of("bad id!"));
        assertThrows(IllegalArgumentException.class, () -> AlgorithmId.of(""));
    }

    @Test
    void externalRegistrationIsConflictSafe() {
        AlgorithmInfo info = new AlgorithmInfo(AlgorithmId.of("CUSTOM-TEST-ALG"),
                "Custom", AlgorithmFamily.HASH, SecurityStatus.RECOMMENDED,
                0, 0, 0, Set.of(), false, false, false, "test");
        AlgorithmCatalog.registerExternal(info);
        assertTrue(AlgorithmId.of("CUSTOM-TEST-ALG").isKnown());
        AlgorithmInfo conflicting = new AlgorithmInfo(info.id(), "Other",
                AlgorithmFamily.HASH, SecurityStatus.ACCEPTABLE, 0, 0, 0, Set.of(),
                false, false, false, "other");
        assertThrows(ConfigurationException.class, () -> AlgorithmCatalog.registerExternal(conflicting));
    }

    @Test
    void catalogIdsAreUnique() {
        Set<String> ids = new HashSet<>();
        AlgorithmCatalog.all().forEach(info -> assertTrue(ids.add(info.id().id())));
    }
}