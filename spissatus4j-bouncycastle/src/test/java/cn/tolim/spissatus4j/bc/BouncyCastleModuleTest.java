package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import cn.tolim.spissatus4j.bc.fips.BcFipsSupport;
import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class BouncyCastleModuleTest {

    @Test
    void moduleIdentityIsStable() {
        BouncyCastleModule module = new BouncyCastleModule();
        assertEquals("bouncycastle", module.moduleId());
        assertEquals(250, module.order());
    }

    @Test
    void contributeRegistersProviderAndBcJcaProvider() {
        BouncyCastleModule module = new BouncyCastleModule();
        TestModuleContext context = new TestModuleContext();

        module.contribute(context);

        List<AlgorithmProvider> providers = context.algorithmProviders();
        assertEquals(1, providers.size());
        AlgorithmProvider registered = providers.get(0);
        assertInstanceOf(BouncyCastleAlgorithmProvider.class, registered);
        assertEquals("bouncycastle", registered.providerId());
        assertEquals(90, registered.priority());
        assertTrue(registered.supports(AlgorithmId.AES_GCM));
        assertTrue(registered.supports(AlgorithmId.ARGON2ID));
        assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
    }

    @Test
    void disabledModuleContributesNothing() {
        BouncyCastleModule module = new BouncyCastleModule();
        TestModuleContext context = new TestModuleContext(
                Map.of(BouncyCastleModule.SETTING_ENABLED, "false"));

        module.contribute(context);

        assertFalse(context.hasAnyRegistration());
        assertTrue(context.attributes().isEmpty());
    }

    @Test
    void fipsModeWithoutFipsProviderFailsStartup() {
        assumeFalse(BcFipsSupport.isFipsAvailable(), "a FIPS provider is on the class path");
        BouncyCastleModule module = new BouncyCastleModule();
        TestModuleContext context = new TestModuleContext(
                Map.of(BouncyCastleModule.SETTING_FIPS_ENABLED, "true"));

        ConfigurationException failure =
                assertThrows(ConfigurationException.class, () -> module.contribute(context));

        assertEquals(ErrorCode.SELF_CHECK_FAILED, failure.errorCode());
        assertFalse(context.hasAnyRegistration());
        assertTrue(failure.getMessage().contains("FIPS"));
    }

    @Test
    void invalidBooleanSettingIsRejected() {
        BouncyCastleModule module = new BouncyCastleModule();
        TestModuleContext context = new TestModuleContext(
                Map.of(BouncyCastleModule.SETTING_ENABLED, "sometimes"));

        ConfigurationException failure =
                assertThrows(ConfigurationException.class, () -> module.contribute(context));

        assertEquals(ErrorCode.CONFIGURATION_INVALID, failure.errorCode());
        assertFalse(context.hasAnyRegistration());
    }

    @Test
    void repeatedContributionKeepsSingleJcaProviderRegistration() {
        BouncyCastleModule module = new BouncyCastleModule();
        module.contribute(new TestModuleContext());
        Provider registered = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(registered);

        TestModuleContext second = new TestModuleContext();
        module.contribute(second);

        assertSame(registered, Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
        assertEquals(1, second.algorithmProviders().size());
    }

    @Test
    void moduleSelfCheckDelegatesToProvider() {
        BouncyCastleModule module = new BouncyCastleModule();
        module.contribute(new TestModuleContext());

        SelfCheckReport report = module.selfCheck();

        assertEquals(HealthStatus.UP, report.overall());
        assertFalse(report.checks().isEmpty());
        assertTrue(report.checks().stream()
                .allMatch(check -> check.checkId().startsWith("module.bouncycastle.")));
        assertTrue(report.failures().isEmpty());
    }

    @Test
    void serviceLoaderDiscoversModule() {
        List<SpissatusModule> modules = ServiceLoader.load(SpissatusModule.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();

        assertTrue(modules.stream().anyMatch(module -> module instanceof BouncyCastleModule
                && "bouncycastle".equals(module.moduleId())));
    }
}