package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.interop.BcInteropVerifier;
import cn.tolim.spissatus4j.bc.interop.BcInteropVerifier.InteropReport;
import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class BcInteropVerifierTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();

    @Test
    void allInteroperabilityChecksPass() {
        InteropReport report = new BcInteropVerifier().verifyAll();

        assertTrue(report.aesGcm(), "AES-GCM interop failed: " + report.failures());
        assertTrue(report.digest(), "digest interop failed: " + report.failures());
        assertTrue(report.signature(), "signature interop failed: " + report.failures());
        assertTrue(report.failures().isEmpty());
        assertTrue(report.passed());
    }

    @Test
    void individualChecksPopulateTheirOwnFlag() {
        BcInteropVerifier verifier = new BcInteropVerifier(PROVIDER.jcaProvider());

        InteropReport aes = verifier.verifyAesGcmInterop();
        assertTrue(aes.aesGcm());
        assertFalse(aes.digest());
        assertFalse(aes.signature());
        assertTrue(aes.failures().isEmpty());

        InteropReport digests = verifier.verifyDigestInterop();
        assertFalse(digests.aesGcm());
        assertTrue(digests.digest());
        assertFalse(digests.signature());
        assertTrue(digests.failures().isEmpty());

        InteropReport signatures = verifier.verifySignatureInterop();
        assertFalse(signatures.aesGcm());
        assertFalse(signatures.digest());
        assertTrue(signatures.signature());
        assertTrue(signatures.failures().isEmpty());
    }

    @Test
    void reportIsImmutableAndPassedRequiresEverything() {
        List<String> failures = new ArrayList<>();
        InteropReport report = new InteropReport(true, true, true, failures);
        failures.add("mutation");

        assertEquals(List.of(), report.failures());
        assertTrue(report.passed());

        assertFalse(new InteropReport(false, true, true, List.of()).passed());
        assertFalse(new InteropReport(true, true, true, List.of("failed")).passed());
    }
}