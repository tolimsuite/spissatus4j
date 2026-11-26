package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.exception.RuntimeSecurityException;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import org.junit.jupiter.api.Test;

class ExceptionContractTest {

    @Test
    void hierarchyIsSealedAndCarriesErrorCodes() {
        SpissatusException[] all = {
                new ConfigurationException("bad config"),
                new KeyException(ErrorCode.KEY_NOT_FOUND, "missing"),
                new CryptoException(ErrorCode.PROVIDER_FAILURE, "provider"),
                new PolicyException(ErrorCode.POLICY_DENIED, "denied"),
                new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "bad envelope"),
                new AuditException(ErrorCode.AUDIT_FAILURE, "audit"),
                new RuntimeSecurityException(ErrorCode.RUNTIME_UNAVAILABLE, "runtime")
        };
        for (SpissatusException exception : all) {
            assertTrue(exception.toSafeString().contains(exception.errorCode().name()));
            assertFalse(exception.toSafeString().contains("secret"));
        }
        assertEquals(7, SpissatusException.class.getPermittedSubclasses().length);
    }

    @Test
    void authenticationFailureMessageIsGeneric() {
        CryptoException failure = CryptoException.authenticationFailed(AlgorithmId.AES_GCM);
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, failure.errorCode());
        assertFalse(failure.getMessage().toLowerCase().contains("tag"));
        assertFalse(failure.getMessage().toLowerCase().contains("padding"));
        assertFalse(failure.getMessage().contains("AES"));
    }

    @Test
    void unsupportedAlgorithmMessageNamesOnlyTheAlgorithm() {
        CryptoException failure = CryptoException.unsupported(AlgorithmId.of("CUSTOM"));
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, failure.errorCode());
        assertTrue(failure.getMessage().contains("CUSTOM"));
    }
}