package cn.tolim.spissatus4j.key.manager;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.UNWRAP;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.WRAP;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeyManagerDependencies;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.key.support.TestSupport;
import cn.tolim.spissatus4j.key.support.TestSupport.MutableClock;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingAuditTrail;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingKeyWrapper;
import cn.tolim.spissatus4j.key.support.TestSupport.StubPolicyEngine;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyManagerFactoryImplTest {

    @TempDir
    Path directory;

    private KeyManagerFactoryImpl factory;
    private StubPolicyEngine policy;
    private RecordingAuditTrail audit;
    private MutableClock clock;
    private CallerContext caller;

    @BeforeEach
    void setUp() {
        factory = new KeyManagerFactoryImpl();
        policy = new StubPolicyEngine();
        audit = new RecordingAuditTrail();
        clock = new MutableClock(Instant.parse("2026-04-01T00:00:00Z"));
        caller = TestSupport.caller();
    }

    @Test
    void buildsMemoryManagerAndUsesExtraWrapper() {
        assertEquals("default-key-manager", factory.factoryId());
        RecordingKeyWrapper stub = new RecordingKeyWrapper("gm-like-stub",
                Set.of(AlgorithmId.AES_KW));
        KeyManager manager = factory.create(dependencies(
                Map.of(KeyManagerFactoryImpl.SETTING_PROVIDER, "memory"), List.of(stub)));
        assertEquals(DefaultKeyManager.class, manager.getClass());
        assertEquals("memory", ((DefaultKeyManager) manager).providerId());

        KeyDescriptor kek = manager.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_KW, Set.of(WRAP, UNWRAP))
                .build(), caller);
        byte[] dek = new byte[32];
        for (int i = 0; i < dek.length; i++) {
            dek[i] = (byte) (0x10 + i);
        }
        byte[] wrapped = manager.wrapKey(kek.keyId(), KeyVersion.first(), AlgorithmId.AES_KW,
                dek, caller);
        assertEquals(1, stub.wrapCount(), "the supplied wrapper must take precedence");
        assertArrayEquals(dek, manager.unwrapKey(kek.keyId(), KeyVersion.first(),
                AlgorithmId.AES_KW, wrapped, caller));
        assertEquals(1, stub.unwrapCount());
        manager.close();
    }

    @Test
    void buildsFileManagerThatPersistsAcrossFactories() {
        Path keyDirectory = directory.resolve("file-keys");
        Map<String, String> settings = Map.of(
                KeyManagerFactoryImpl.SETTING_PROVIDER, "file",
                KeyManagerFactoryImpl.SETTING_FILE_DIRECTORY, keyDirectory.toString(),
                KeyManagerFactoryImpl.SETTING_MASTER_PASSWORD, "master-password",
                KeyManagerFactoryImpl.SETTING_RETAIN_VERSIONS, "2");

        KeyManager manager = factory.create(dependencies(settings, List.of()));
        assertEquals("file", ((DefaultKeyManager) manager).providerId());
        KeyDescriptor descriptor = manager.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                .rotationPolicy(null)
                .build(), caller);
        assertEquals(2, descriptor.rotationPolicy().retainVersions());
        assertTrue(descriptor.createdAt().equals(clock.instant()));
        KeyDescriptor rotated = manager.rotate(descriptor.keyId(), caller);
        assertEquals(2, rotated.version().value());
        assertEquals(KeyState.DEACTIVATED, manager.describe(descriptor.keyId(),
                KeyVersion.first(), caller).orElseThrow().state());
        manager.close();

        KeyManager reopened = factory.create(dependencies(settings, List.of()));
        assertTrue(reopened.describe(descriptor.keyId(), KeyVersion.first(), caller)
                .isPresent());
        assertTrue(reopened.describe(descriptor.keyId(), rotated.version(), caller)
                .isPresent());
        assertNotNull(reopened.secretKey(descriptor.keyId(), KeyVersion.first(), DECRYPT,
                caller));
        assertNotNull(reopened.secretKey(descriptor.keyId(), rotated.version(), ENCRYPT,
                caller));
        reopened.close();
    }

    @Test
    void buildsEnvironmentAndKeyStoreProviders() {
        KeyManager environment = factory.create(dependencies(Map.of(
                KeyManagerFactoryImpl.SETTING_PROVIDER, "environment",
                KeyManagerFactoryImpl.SETTING_ENVIRONMENT_PREFIX, "UNITTEST_"), List.of()));
        assertEquals("environment", ((DefaultKeyManager) environment).providerId());
        environment.close();

        KeyManager keyStore = factory.create(dependencies(Map.of(
                KeyManagerFactoryImpl.SETTING_PROVIDER, "keystore",
                KeyManagerFactoryImpl.SETTING_KEYSTORE_PATH,
                directory.resolve("factory.jks").toString(),
                KeyManagerFactoryImpl.SETTING_KEYSTORE_PASSWORD, "changeit"), List.of()));
        assertEquals("keystore", ((DefaultKeyManager) keyStore).providerId());
        KeyDescriptor descriptor = keyStore.generate(KeyGenerationRequest.builder(KeyType.AES,
                AlgorithmId.AES_GCM, Set.of(ENCRYPT)).build(), caller);
        assertNotNull(keyStore.secretKey(descriptor.keyId(), KeyVersion.first(), ENCRYPT,
                caller));
        keyStore.close();
    }

    @Test
    void rejectsInvalidSettings() {
        ConfigurationException missingDirectory = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "file"), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, missingDirectory.errorCode());

        ConfigurationException missingPassword = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "file",
                        KeyManagerFactoryImpl.SETTING_FILE_DIRECTORY,
                        directory.resolve("no-password").toString()), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, missingPassword.errorCode());

        ConfigurationException unknown = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "vault"), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, unknown.errorCode());

        ConfigurationException retain = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "memory",
                        KeyManagerFactoryImpl.SETTING_RETAIN_VERSIONS, "0"), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, retain.errorCode());

        ConfigurationException missingKeyStorePassword = assertThrows(
                ConfigurationException.class, () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "keystore",
                        KeyManagerFactoryImpl.SETTING_KEYSTORE_PATH,
                        directory.resolve("nopass.jks").toString()), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, missingKeyStorePassword.errorCode());

        ConfigurationException badPrefix = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "environment",
                        KeyManagerFactoryImpl.SETTING_ENVIRONMENT_PREFIX, "bad-prefix"),
                        List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, badPrefix.errorCode());

        ConfigurationException nullDependencies = assertThrows(ConfigurationException.class,
                () -> factory.create(null));
        assertEquals(ErrorCode.MISSING_DEPENDENCY, nullDependencies.errorCode());
    }

    @Test
    void selectsExactlyOneContributedProvider() {
        TestKeyProvider contributed = new TestKeyProvider("contributed-test");

        KeyManager implicit = factory.create(dependencies(Map.of(), List.of(),
                List.of(contributed)));
        assertEquals("contributed-test", ((DefaultKeyManager) implicit).providerId());
        implicit.close();

        KeyManager module = factory.create(dependencies(
                Map.of(KeyManagerFactoryImpl.SETTING_PROVIDER, "module"), List.of(),
                List.of(contributed)));
        assertEquals("contributed-test", ((DefaultKeyManager) module).providerId());
        module.close();

        KeyManager provided = factory.create(dependencies(Map.of(
                KeyManagerFactoryImpl.SETTING_PROVIDER, "provided",
                KeyManagerFactoryImpl.SETTING_PROVIDER_ID, "contributed-test"), List.of(),
                List.of(contributed)));
        assertEquals("contributed-test", ((DefaultKeyManager) provided).providerId());
        provided.close();
    }

    @Test
    void explicitProviderSettingTakesPrecedenceOverContributedProvider() {
        TestKeyProvider contributed = new TestKeyProvider("contributed-test");
        KeyManager manager = factory.create(dependencies(
                Map.of(KeyManagerFactoryImpl.SETTING_PROVIDER, "memory"), List.of(),
                List.of(contributed)));
        assertEquals("memory", ((DefaultKeyManager) manager).providerId());
        manager.close();
    }

    @Test
    void contributedProviderSelectionFailsClosedOnAbsenceOrAmbiguity() {
        KeyManager absent = factory.create(dependencies(Map.of(), List.of(), List.of()));
        assertEquals("memory", ((DefaultKeyManager) absent).providerId());
        absent.close();

        ConfigurationException explicitAbsent = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "provided"), List.of(), List.of())));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, explicitAbsent.errorCode());

        ConfigurationException ambiguous = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(), List.of(), List.of(
                        new TestKeyProvider("one"), new TestKeyProvider("two")))));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, ambiguous.errorCode());

        ConfigurationException unknownId = assertThrows(ConfigurationException.class,
                () -> factory.create(dependencies(Map.of(
                        KeyManagerFactoryImpl.SETTING_PROVIDER, "provided",
                        KeyManagerFactoryImpl.SETTING_PROVIDER_ID, "missing"), List.of(),
                        List.of(new TestKeyProvider("one")))));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, unknownId.errorCode());

        KeyManager selected = factory.create(dependencies(Map.of(
                KeyManagerFactoryImpl.SETTING_PROVIDER, "provided",
                KeyManagerFactoryImpl.SETTING_PROVIDER_ID, "two"), List.of(),
                List.of(new TestKeyProvider("one"), new TestKeyProvider("two"))));
        assertEquals("two", ((DefaultKeyManager) selected).providerId());
        selected.close();
    }

    private KeyManagerDependencies dependencies(Map<String, String> settings,
                                               List<KeyWrapper> wrappers) {
        return new KeyManagerDependencies(policy, audit, clock, wrappers, settings);
    }

    private KeyManagerDependencies dependencies(Map<String, String> settings,
                                               List<KeyWrapper> wrappers,
                                               List<cn.tolim.spissatus4j.contract.spi.KeyProvider> providers) {
        return new KeyManagerDependencies(policy, audit, clock, wrappers, providers, settings);
    }

    /** Contributed provider double with a stable, distinct provider id. */
    private static final class TestKeyProvider implements
            cn.tolim.spissatus4j.contract.spi.KeyProvider {

        private final String providerId;
        private final cn.tolim.spissatus4j.key.provider.InMemoryKeyProvider delegate =
                new cn.tolim.spissatus4j.key.provider.InMemoryKeyProvider();

        private TestKeyProvider(String providerId) {
            this.providerId = providerId;
        }

        @Override
        public String providerId() {
            return providerId;
        }

        @Override
        public java.util.Optional<cn.tolim.spissatus4j.contract.spi.StoredKey> load(
                cn.tolim.spissatus4j.contract.key.KeyId keyId,
                cn.tolim.spissatus4j.contract.key.KeyVersion version) {
            return delegate.load(keyId, version);
        }

        @Override
        public void save(cn.tolim.spissatus4j.contract.spi.StoredKey storedKey) {
            delegate.save(storedKey);
        }

        @Override
        public boolean delete(cn.tolim.spissatus4j.contract.key.KeyId keyId,
                              cn.tolim.spissatus4j.contract.key.KeyVersion version) {
            return delegate.delete(keyId, version);
        }

        @Override
        public List<cn.tolim.spissatus4j.contract.spi.StoredKey> list(String tenantId) {
            return delegate.list(tenantId);
        }

        @Override
        public cn.tolim.spissatus4j.contract.runtime.HealthStatus health() {
            return delegate.health();
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}