package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.api.Capabilities;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.unified.AlgorithmCandidate;
import cn.tolim.spissatus4j.contract.unified.SelectionCapabilities;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SelectionCapabilitiesTest {

    @Test
    void derivesAvailableCandidatesWithoutProviderTypes() {
        Capabilities capabilities = new Capabilities("1.0.0",
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.CHACHA20_POLY1305),
                List.of(new Capabilities.ProviderCapability("provider-a", 100,
                        Set.of(AlgorithmId.AES_GCM), HealthStatus.UP),
                        new Capabilities.ProviderCapability("provider-b", 90,
                                Set.of(AlgorithmId.CHACHA20_POLY1305), HealthStatus.DOWN)),
                ComplianceMode.STANDARD, false, false, HealthStatus.UP);
        SelectionCapabilities selection = SelectionCapabilities.from(capabilities);
        AlgorithmCandidate aes = selection.candidates().stream()
                .filter(candidate -> candidate.info().id().equals(AlgorithmId.AES_GCM))
                .findFirst().orElseThrow();
        assertTrue(aes.installed());
        assertTrue(aes.compliant());
        assertTrue(aes.available());
        assertEquals(0, aes.rank());

        AlgorithmCandidate chacha = selection.candidates().stream()
                .filter(candidate -> candidate.info().id().equals(AlgorithmId.CHACHA20_POLY1305))
                .findFirst().orElseThrow();
        assertTrue(chacha.installed());
        assertFalse(chacha.available());

        AlgorithmCandidate aesCbc = selection.candidates().stream()
                .filter(candidate -> candidate.info().id().equals(AlgorithmId.AES_CBC))
                .findFirst().orElseThrow();
        assertFalse(aesCbc.installed());
        assertTrue(aesCbc.compliant());
        assertEquals(-1, aesCbc.rank());

        assertEquals(List.of(SelectionProfile.AUTO_AEAD,
                SelectionProfile.AUTO_AEAD_THEN_ETM), selection.profiles());
    }
}