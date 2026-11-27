package cn.tolim.spissatus4j.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.facade.Spissatus;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import cn.tolim.spissatus4j.core.testkit.TestAlgorithmProvider;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FipsRuntimeSelectionTest {

    @Test
    void fipsSettingEnforcesFipsModeAndNonFipsProvidersAreNotAdvertised() {
        CallerContext caller = CallerContext.of("tester", TestKeyManager.TENANT,
                Set.of("crypto-user"));
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(true)
                .trustModule("cn.tolim.spissatus4j.core.test.TestFipsModule")
                .setting("spissatus.fips.enabled", "true")
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .build()) {
            assertEquals(ComplianceMode.FIPS, facade.capabilities().complianceMode());
            assertEquals(true, facade.capabilities().fipsAvailable());
            // The non-FIPS provider remains installed but advertises no usable
            // algorithms in FIPS mode.
            facade.capabilities().providers().stream()
                    .filter(provider -> provider.providerId().equals("test-jca"))
                    .forEach(provider -> assertEquals(0, provider.algorithms().size()));
            byte[] plaintext = "fips path".getBytes(StandardCharsets.UTF_8);
            var data = facade.crypto().encrypt(EncryptRequest.builder(AlgorithmId.AES_GCM,
                    TestKeyManager.KEY_ID, plaintext, caller).aad(AAD.empty()).build());
            assertArrayEquals(plaintext, facade.crypto().decrypt(DecryptRequest.from(data, caller)));
        }
    }
}
