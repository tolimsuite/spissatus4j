package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import cn.tolim.spissatus4j.bc.fips.BcFipsSupport;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import org.junit.jupiter.api.Test;

class BcFipsSupportTest {

    @Test
    void absencePathFailsClosed() {
        assumeFalse(BcFipsSupport.isFipsAvailable(), "a FIPS provider is on the class path");

        assertFalse(BcFipsSupport.isFipsAvailable());
        assertEquals("BCFIPS", BcFipsSupport.providerName());

        ConfigurationException failure = assertThrows(ConfigurationException.class,
                BcFipsSupport::requireFips);
        assertEquals(ErrorCode.SELF_CHECK_FAILED, failure.errorCode());
        assertFalse(failure.getMessage().isEmpty());
    }

    @Test
    void repeatedRequireFipsKeepsFailingWithoutSideEffects() {
        assumeFalse(BcFipsSupport.isFipsAvailable(), "a FIPS provider is on the class path");

        assertThrows(ConfigurationException.class, BcFipsSupport::requireFips);
        assertThrows(ConfigurationException.class, BcFipsSupport::requireFips);
        assertFalse(BcFipsSupport.isFipsAvailable());
    }

    @Test
    void providerNameIsStable() {
        assertTrue(BcFipsSupport.providerName().matches("[A-Z]+"));
        assertEquals("BCFIPS", BcFipsSupport.providerName());
    }
}