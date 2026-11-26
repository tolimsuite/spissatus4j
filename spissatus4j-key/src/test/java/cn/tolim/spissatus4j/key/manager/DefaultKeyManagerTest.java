package cn.tolim.spissatus4j.key.manager;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DERIVE;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.MAC;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.SIGN;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.UNWRAP;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.VERIFY;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.WRAP;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.key.ImportFormat;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyImportRequest;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.RotationPolicy;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import cn.tolim.spissatus4j.key.provider.FileKeyProvider;
import cn.tolim.spissatus4j.key.provider.InMemoryKeyProvider;
import cn.tolim.spissatus4j.key.support.TestSupport;
import cn.tolim.spissatus4j.key.support.TestSupport.MutableClock;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingAuditTrail;
import cn.tolim.spissatus4j.key.support.TestSupport.StubPolicyEngine;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultKeyManagerTest {

    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    private RecordingAuditTrail audit;
    private StubPolicyEngine policy;
    private MutableClock clock;
    private InMemoryKeyProvider provider;
    private DefaultKeyManager manager;
    private CallerContext caller;

    @BeforeEach
    void setUp() {
        audit = new RecordingAuditTrail();
        policy = new StubPolicyEngine();
        clock = new MutableClock(START);
        provider = new InMemoryKeyProvider();
        manager = new DefaultKeyManager(provider, List.of(), policy, audit, clock);
        caller = TestSupport.caller();
    }

    @AfterEach
    void tearDown() {
        manager.close();
    }

    @Test
    void generatesDescribesAndResolvesKeys() {
        KeyDescriptor descriptor = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));

        assertEquals(KeyState.ACTIVE, descriptor.state());
        assertEquals(KeyVersion.first(), descriptor.version());
        assertEquals(Set.of(ENCRYPT, DECRYPT), descriptor.usages());
        assertEquals(256, descriptor.keyBits());
        assertEquals(START, descriptor.createdAt());
        assertEquals(START, descriptor.activatedAt());
        assertNotNull(descriptor.fingerprint());
        assertEquals("memory", manager.providerId());

        Optional<KeyDescriptor> described = manager.describe(descriptor.keyId(),
                KeyVersion.first(), caller);
        assertTrue(described.isPresent());
        assertEquals(descriptor, described.orElseThrow());

        StoredKey stored = provider.load(descriptor.keyId(), KeyVersion.first()).orElseThrow();
        assertFalse(stored.encrypted());
        assertEquals(KeyMaterialCodec.RAW, stored.materialFormat());
        assertEquals(32, stored.material().length);

        KeyDescriptor resolved = manager.resolveForUse(descriptor.keyId(), null, ENCRYPT, caller);
        assertEquals(descriptor.keyId(), resolved.keyId());
        assertEquals(1, resolved.usageCount());
        assertEquals(1, manager.describe(descriptor.keyId(), KeyVersion.first(), caller)
                .orElseThrow().usageCount());

        SecretKey key = manager.secretKey(descriptor.keyId(), KeyVersion.first(), ENCRYPT, caller);
        assertEquals("AES", key.getAlgorithm());

        KeyDescriptor historical = manager.resolveForUse(descriptor.keyId(), 1L, DECRYPT, caller);
        assertEquals(1, historical.usageCount(),
                "processing operations must not increment the protecting usage counter");

        assertEquals(HealthStatus.UP, manager.health());
        assertTrue(audit.has(AuditEventType.KEY_GENERATED));
        assertFalse(policy.requests().isEmpty());
        assertTrue(manager.list("default", caller).stream()
                .anyMatch(item -> item.keyId().equals(descriptor.keyId())));
        assertEquals(1, manager.versions(descriptor.keyId(), caller).size());
    }

    @Test
    void enforcesUsageIsolationAndMissingKeyErrors() {
        KeyDescriptor macKey = generate(KeyType.HMAC, AlgorithmId.HMAC_SHA256, 0, Set.of(MAC));
        SecretKey secretKey = manager.secretKey(macKey.keyId(), KeyVersion.first(), MAC, caller);
        assertEquals("HmacSHA256", secretKey.getAlgorithm());

        KeyException usageViolation = assertThrows(KeyException.class,
                () -> manager.resolveForUse(macKey.keyId(), null, DECRYPT, caller));
        assertEquals(ErrorCode.KEY_USAGE_VIOLATION, usageViolation.errorCode());
        KeyException materialViolation = assertThrows(KeyException.class,
                () -> manager.secretKey(macKey.keyId(), KeyVersion.first(), DECRYPT, caller));
        assertEquals(ErrorCode.KEY_USAGE_VIOLATION, materialViolation.errorCode());

        KeyDescriptor aesKey = generate(KeyType.AES, AlgorithmId.AES_GCM, 128, Set.of(ENCRYPT));
        assertEquals(128, aesKey.keyBits());
        KeyException signViolation = assertThrows(KeyException.class,
                () -> manager.resolveForUse(aesKey.keyId(), null, SIGN, caller));
        assertEquals(ErrorCode.KEY_USAGE_VIOLATION, signViolation.errorCode());

        KeyId missing = KeyId.of("missing-key");
        KeyException notFound = assertThrows(KeyException.class,
                () -> manager.resolveForUse(missing, null, ENCRYPT, caller));
        assertEquals(ErrorCode.KEY_NOT_FOUND, notFound.errorCode());
        assertTrue(manager.describe(missing, KeyVersion.first(), caller).isEmpty());

        KeyException missingVersion = assertThrows(KeyException.class,
                () -> manager.resolveForUse(aesKey.keyId(), 9L, DECRYPT, caller));
        assertEquals(ErrorCode.KEY_VERSION_NOT_FOUND, missingVersion.errorCode());

        KeyException mismatch = assertThrows(KeyException.class, () -> manager.generate(
                KeyGenerationRequest.builder(KeyType.HMAC, AlgorithmId.AES_GCM, Set.of(MAC))
                        .build(), caller));
        assertEquals(ErrorCode.INVALID_PARAMETER, mismatch.errorCode());
    }

    @Test
    void enforcesTenantIsolationAndAllowsCrossTenantRoles() {
        KeyDescriptor descriptor = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));
        CallerContext otherTenant = TestSupport.caller("acme", Set.of("crypto-user"));

        PolicyException resolveDenied = assertThrows(PolicyException.class,
                () -> manager.resolveForUse(descriptor.keyId(), null, ENCRYPT, otherTenant));
        assertEquals(ErrorCode.TENANT_VIOLATION, resolveDenied.errorCode());
        assertThrows(PolicyException.class,
                () -> manager.describe(descriptor.keyId(), KeyVersion.first(), otherTenant));
        assertThrows(PolicyException.class, () -> manager.list("default", otherTenant));
        assertThrows(PolicyException.class, () -> manager.generate(
                KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                        .tenantId("default").build(), otherTenant));

        CallerContext crossTenant = TestSupport.caller("acme",
                Set.of("crypto-cross-tenant"));
        assertTrue(manager.describe(descriptor.keyId(), KeyVersion.first(), crossTenant)
                .isPresent());
        KeyDescriptor resolved = manager.resolveForUse(descriptor.keyId(), null, ENCRYPT,
                crossTenant);
        assertEquals("default", resolved.tenantId());
        assertNotNull(manager.secretKey(descriptor.keyId(), KeyVersion.first(), ENCRYPT,
                crossTenant));

        CallerContext admin = caller("acme", Set.of("crypto-admin"));
        assertTrue(manager.describe(descriptor.keyId(), KeyVersion.first(), admin).isPresent());
    }

    @Test
    void configuredCrossTenantRolesReplaceTheHardcodedDefaults() {
        DefaultKeyManager custom = new DefaultKeyManager(new InMemoryKeyProvider(), List.of(),
                policy, audit, clock, 3, Set.of("break-glass"));
        KeyDescriptor descriptor = custom.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                .tenantId("default").build(), caller);
        CallerContext breakGlass = caller("acme", Set.of("break-glass"));
        assertTrue(custom.describe(descriptor.keyId(), KeyVersion.first(), breakGlass).isPresent());
        CallerContext defaultRole = caller("acme", Set.of("crypto-cross-tenant"));
        assertThrows(PolicyException.class,
                () -> custom.describe(descriptor.keyId(), KeyVersion.first(), defaultRole));
        custom.close();
    }

    @Test
    void enforcesLifecycleTransitionsAndAudits() {
        KeyDescriptor descriptor = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));
        KeyId keyId = descriptor.keyId();
        KeyVersion version = KeyVersion.first();

        KeyException blankReason = assertThrows(KeyException.class,
                () -> manager.revoke(keyId, version, caller, "   "));
        assertEquals(ErrorCode.INVALID_PARAMETER, blankReason.errorCode());

        KeyDescriptor deactivated = manager.deactivate(keyId, version, caller);
        assertEquals(KeyState.DEACTIVATED, deactivated.state());
        assertEquals(KeyState.DEACTIVATED,
                manager.resolveForUse(keyId, 1L, DECRYPT, caller).state());
        KeyException notActive = assertThrows(KeyException.class,
                () -> manager.resolveForUse(keyId, null, ENCRYPT, caller));
        assertEquals(ErrorCode.KEY_NOT_ACTIVE, notActive.errorCode());

        assertEquals(KeyState.ACTIVE, manager.activate(keyId, version, caller).state());
        KeyDescriptor compromised = manager.compromise(keyId, version, caller,
                "  leaked\nmaterial  ");
        assertEquals(KeyState.COMPROMISED, compromised.state());
        KeyException compromisedUse = assertThrows(KeyException.class,
                () -> manager.resolveForUse(keyId, 1L, DECRYPT, caller));
        assertEquals(ErrorCode.KEY_NOT_ACTIVE, compromisedUse.errorCode());

        KeyDescriptor destroyed = manager.destroy(keyId, version, caller);
        assertEquals(KeyState.DESTROYED_COMPROMISED, destroyed.state());
        Optional<KeyDescriptor> described = manager.describe(keyId, version, caller);
        assertTrue(described.isPresent());
        assertEquals(KeyState.DESTROYED_COMPROMISED, described.orElseThrow().state());

        KeyException destroyedAccess = assertThrows(KeyException.class,
                () -> manager.secretKey(keyId, version, DECRYPT, caller));
        assertEquals(ErrorCode.KEY_DESTROYED, destroyedAccess.errorCode());
        KeyException destroyedAgain = assertThrows(KeyException.class,
                () -> manager.destroy(keyId, version, caller));
        assertEquals(ErrorCode.ILLEGAL_KEY_TRANSITION, destroyedAgain.errorCode());
        KeyException revokedAfterDestroy = assertThrows(KeyException.class,
                () -> manager.revoke(keyId, version, caller, "after destruction"));
        assertEquals(ErrorCode.ILLEGAL_KEY_TRANSITION, revokedAfterDestroy.errorCode());

        AuditEvent compromiseEvent = audit.first(AuditEventType.KEY_COMPROMISED);
        assertNotNull(compromiseEvent);
        assertEquals("leaked material", compromiseEvent.details().get("reason"));
        assertFalse(compromiseEvent.details().get("reason").contains("\n"));
        assertTrue(audit.has(AuditEventType.KEY_DEACTIVATED));
        assertTrue(audit.has(AuditEventType.KEY_ACTIVATED));
        assertTrue(audit.has(AuditEventType.KEY_DESTROYED));

        KeyDescriptor second = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));
        manager.deactivate(second.keyId(), KeyVersion.first(), caller);
        manager.revoke(second.keyId(), KeyVersion.first(), caller, "incident report");
        KeyDescriptor terminal = manager.destroy(second.keyId(), KeyVersion.first(), caller);
        assertEquals(KeyState.DESTROYED, terminal.state());
        assertEquals(KeyState.ACTIVE,
                manager.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_GCM, Set.of(ENCRYPT)).build(), caller).state());
    }

    @Test
    void importedKeysStartBeforeActivationAndFollowTransitions() {
        byte[] raw = new byte[32];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) i;
        }
        KeyId keyId = KeyId.of("imported-aes");
        KeyDescriptor imported = manager.importKey(KeyImportRequest.builder(keyId,
                        ImportFormat.RAW, raw, KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .tenantId("default")
                .build(), caller);

        assertEquals(KeyState.PRE_ACTIVATION, imported.state());
        assertEquals(256, imported.keyBits());
        KeyException illegal = assertThrows(KeyException.class,
                () -> manager.deactivate(keyId, KeyVersion.first(), caller));
        assertEquals(ErrorCode.ILLEGAL_KEY_TRANSITION, illegal.errorCode());
        assertThrows(KeyException.class,
                () -> manager.resolveForUse(keyId, null, ENCRYPT, caller));

        manager.activate(keyId, KeyVersion.first(), caller);
        assertArrayEquals(raw,
                manager.secretKey(keyId, KeyVersion.first(), ENCRYPT, caller).getEncoded());
        KeyException exportDenied = assertThrows(KeyException.class,
                () -> manager.exportPublicKey(keyId, KeyVersion.first(), caller));
        assertEquals(ErrorCode.KEY_EXPORT_DENIED, exportDenied.errorCode());

        manager.deactivate(keyId, KeyVersion.first(), caller);
        assertEquals(KeyState.REVOKED,
                manager.revoke(keyId, KeyVersion.first(), caller, "rotation overdue").state());
        assertEquals(KeyState.DESTROYED,
                manager.destroy(keyId, KeyVersion.first(), caller).state());
        assertEquals(KeyState.DESTROYED,
                manager.describe(keyId, KeyVersion.first(), caller).orElseThrow().state());
    }

    @Test
    void lazilyRotatesByAgeAndRetainsHistoricalVersions() {
        KeyId keyId = KeyId.of("rotating-aes");
        manager.generate(KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .keyId(keyId)
                .rotationPolicy(new RotationPolicy(Duration.ofHours(1), 0, 3))
                .attributes(Map.of("team", "crypto"))
                .build(), caller);

        clock.advance(Duration.ofHours(2));
        KeyDescriptor version2 = manager.resolveForUse(keyId, null, ENCRYPT, caller);
        assertEquals(2, version2.version().value());
        assertEquals(KeyState.ACTIVE, version2.state());
        assertEquals(1, version2.usageCount());
        assertEquals(Set.of(ENCRYPT, DECRYPT), version2.usages());
        assertEquals("crypto", version2.attributes().get("team"));
        assertEquals("default", version2.tenantId());
        assertEquals(KeyState.DEACTIVATED, manager.describe(keyId, KeyVersion.first(), caller)
                .orElseThrow().state());

        SecretKey oldKey = manager.secretKey(keyId, KeyVersion.first(), DECRYPT, caller);
        SecretKey newKey = manager.secretKey(keyId, version2.version(), DECRYPT, caller);
        assertFalse(Arrays.equals(oldKey.getEncoded(), newKey.getEncoded()),
                "rotation must create fresh key material");

        manager.rotate(keyId, caller);
        manager.rotate(keyId, caller);
        List<KeyDescriptor> versions = manager.versions(keyId, caller);
        assertEquals(4, versions.size());
        assertEquals(KeyState.DESTROYED,
                manager.describe(keyId, KeyVersion.first(), caller).orElseThrow().state());
        KeyException destroyed = assertThrows(KeyException.class,
                () -> manager.secretKey(keyId, KeyVersion.first(), DECRYPT, caller));
        assertEquals(ErrorCode.KEY_DESTROYED, destroyed.errorCode());
        assertTrue(audit.has(AuditEventType.KEY_ROTATED));
        assertTrue(audit.has(AuditEventType.KEY_DESTROYED));
    }

    @Test
    void rotatesWhenOperationThresholdIsReached() {
        KeyId keyId = KeyId.of("operation-rotated");
        manager.generate(KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .keyId(keyId)
                .rotationPolicy(new RotationPolicy(null, 2, 3))
                .build(), caller);

        assertEquals(1, manager.resolveForUse(keyId, null, ENCRYPT, caller).version().value());
        assertEquals(1, manager.resolveForUse(keyId, null, ENCRYPT, caller).version().value());
        assertEquals(2, manager.resolveForUse(keyId, null, ENCRYPT, caller).version().value());
    }

    @Test
    void policyDecisionsAreFailClosedAndAudited() {
        policy.setOutcome(PolicyDecision.Outcome.DENY);
        PolicyException denied = assertThrows(PolicyException.class, () -> manager.generate(
                KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                        .build(), caller));
        assertEquals(ErrorCode.POLICY_DENIED, denied.errorCode());
        assertTrue(provider.list(null).isEmpty(), "policy denial must prevent key creation");
        assertTrue(audit.has(AuditEventType.POLICY_DENIED));

        policy.setOutcome(PolicyDecision.Outcome.ALLOW);
        KeyDescriptor descriptor = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));
        policy.setOutcome(PolicyDecision.Outcome.DENY);
        PolicyException deniedRead = assertThrows(PolicyException.class,
                () -> manager.describe(descriptor.keyId(), KeyVersion.first(), caller));
        assertEquals(ErrorCode.POLICY_DENIED, deniedRead.errorCode());

        policy.setOutcome(PolicyDecision.Outcome.WARN);
        List<KeyDescriptor> warned = manager.versions(descriptor.keyId(), caller);
        assertFalse(warned.isEmpty());
        assertTrue(audit.has(AuditEventType.POLICY_WARNING));

        policy.setUnavailable(true);
        PolicyException unavailable = assertThrows(PolicyException.class,
                () -> manager.describe(descriptor.keyId(), KeyVersion.first(), caller));
        assertEquals(ErrorCode.POLICY_UNAVAILABLE, unavailable.errorCode());
    }

    @Test
    void wrapsAndUnwrapsDataEncryptionKeys() {
        KeyDescriptor aesKek = manager.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_KW, Set.of(WRAP, UNWRAP))
                .build(), caller);
        byte[] dek = new byte[32];
        for (int i = 0; i < dek.length; i++) {
            dek[i] = (byte) (0x40 + i);
        }
        byte[] wrapped = manager.wrapKey(aesKek.keyId(), KeyVersion.first(),
                AlgorithmId.AES_KW, dek, caller);
        assertEquals(dek.length + 8, wrapped.length);
        assertArrayEquals(dek, manager.unwrapKey(aesKek.keyId(), KeyVersion.first(),
                AlgorithmId.AES_KW, wrapped, caller));

        byte[] tampered = wrapped.clone();
        tampered[3] ^= 0x01;
        CryptoException authenticationFailure = assertThrows(CryptoException.class,
                () -> manager.unwrapKey(aesKek.keyId(), KeyVersion.first(),
                        AlgorithmId.AES_KW, tampered, caller));
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, authenticationFailure.errorCode());

        KeyDescriptor rsaKek = manager.generate(KeyGenerationRequest.builder(KeyType.RSA,
                        AlgorithmId.RSA_OAEP, Set.of(WRAP, UNWRAP))
                .keyBits(2048)
                .build(), caller);
        byte[] wrappedRsa = manager.wrapKey(rsaKek.keyId(), KeyVersion.first(),
                AlgorithmId.RSA_OAEP, dek, caller);
        assertEquals(256, wrappedRsa.length);
        assertArrayEquals(dek, manager.unwrapKey(rsaKek.keyId(), KeyVersion.first(),
                AlgorithmId.RSA_OAEP, wrappedRsa, caller));

        byte[] wrappedPkcs1 = manager.wrapKey(rsaKek.keyId(), KeyVersion.first(),
                AlgorithmId.RSA_PKCS1, dek, caller);
        assertArrayEquals(dek, manager.unwrapKey(rsaKek.keyId(), KeyVersion.first(),
                AlgorithmId.RSA_PKCS1, wrappedPkcs1, caller));
        assertTrue(audit.has(AuditEventType.WRAP));
        assertTrue(audit.has(AuditEventType.UNWRAP));
    }

    @Test
    void importsJwkPemAndRawAndDeniesPrivateExport() throws Exception {
        byte[] raw = new byte[32];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (i + 1);
        }
        KeyId rawId = KeyId.of("raw-aes");
        KeyDescriptor rawDescriptor = manager.importKey(KeyImportRequest.builder(rawId,
                        ImportFormat.RAW, raw, KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .build(), caller);
        assertEquals(KeyState.PRE_ACTIVATION, rawDescriptor.state());
        manager.activate(rawId, KeyVersion.first(), caller);
        assertArrayEquals(raw,
                manager.secretKey(rawId, KeyVersion.first(), ENCRYPT, caller).getEncoded());

        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsaPair = rsaGenerator.generateKeyPair();
        RSAPublicKey rsaPublic = (RSAPublicKey) rsaPair.getPublic();
        String jwk = "{\"kty\":\"RSA\",\"n\":\"" + unsignedBase64(rsaPublic.getModulus())
                + "\",\"e\":\"" + unsignedBase64(rsaPublic.getPublicExponent()) + "\"}";
        KeyId jwkId = KeyId.of("jwk-rsa");
        KeyDescriptor jwkDescriptor = manager.importKey(KeyImportRequest.builder(jwkId,
                        ImportFormat.JWK, jwk.getBytes(StandardCharsets.UTF_8), KeyType.RSA,
                        AlgorithmId.RSA_OAEP, Set.of(ENCRYPT))
                .build(), caller);
        assertEquals(KeyState.PRE_ACTIVATION, jwkDescriptor.state());
        assertEquals(2048, jwkDescriptor.keyBits());
        manager.activate(jwkId, KeyVersion.first(), caller);
        PublicKey importedPublic = manager.publicKey(jwkId, KeyVersion.first(), ENCRYPT,
                caller);
        assertArrayEquals(rsaPair.getPublic().getEncoded(), importedPublic.getEncoded());
        assertArrayEquals(rsaPair.getPublic().getEncoded(),
                manager.exportPublicKey(jwkId, KeyVersion.first(), caller));

        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecPair = ecGenerator.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'})
                        .encodeToString(ecPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        KeyId pemId = KeyId.of("pem-ec");
        KeyDescriptor pemDescriptor = manager.importKey(KeyImportRequest.builder(pemId,
                        ImportFormat.PEM, pem.getBytes(StandardCharsets.UTF_8), KeyType.EC,
                        AlgorithmId.ECDSA_P256, Set.of(SIGN))
                .build(), caller);
        assertEquals(KeyState.PRE_ACTIVATION, pemDescriptor.state());
        assertEquals(256, pemDescriptor.keyBits());
        assertEquals(KeyMaterialCodec.PKCS8,
                provider.load(pemId, KeyVersion.first()).orElseThrow().materialFormat());
        manager.activate(pemId, KeyVersion.first(), caller);
        PrivateKey importedPrivate = manager.privateKey(pemId, KeyVersion.first(), SIGN,
                caller);
        assertArrayEquals(ecPair.getPrivate().getEncoded(), importedPrivate.getEncoded());
        KeyException exportDenied = assertThrows(KeyException.class,
                () -> manager.exportPublicKey(pemId, KeyVersion.first(), caller));
        assertEquals(ErrorCode.KEY_EXPORT_DENIED, exportDenied.errorCode());
        assertTrue(audit.has(AuditEventType.KEY_EXPORT_DENIED));

        KeyException malformed = assertThrows(KeyException.class,
                () -> manager.importKey(KeyImportRequest.builder(KeyId.of("bad-jwk"),
                                ImportFormat.JWK, "{\"kty\":\"RSA\",\"n\":\"%%\"}"
                                        .getBytes(StandardCharsets.UTF_8),
                                KeyType.RSA, AlgorithmId.RSA_OAEP, Set.of(ENCRYPT))
                        .build(), caller));
        assertEquals(ErrorCode.KEY_IMPORT_FAILED, malformed.errorCode());
    }

    @Test
    void generatesSupportedKeyTypesAndEnforcesMinimumSizes() {
        KeyDescriptor ed25519 = generate(KeyType.ED25519, AlgorithmId.ED25519, 0, Set.of(SIGN));
        assertEquals(Set.of(SIGN, VERIFY), ed25519.usages());
        assertEquals(256, ed25519.keyBits());
        PrivateKey signingKey = manager.privateKey(ed25519.keyId(), KeyVersion.first(), SIGN,
                caller);
        PublicKey verifyingKey = manager.publicKey(ed25519.keyId(), KeyVersion.first(), VERIFY,
                caller);
        assertNotNull(signingKey);
        assertArrayEquals(verifyingKey.getEncoded(),
                manager.exportPublicKey(ed25519.keyId(), KeyVersion.first(), caller));

        KeyDescriptor ed448 = generate(KeyType.ED448, AlgorithmId.ED448, 0, Set.of(SIGN));
        assertEquals(456, ed448.keyBits());
        assertNotNull(manager.privateKey(ed448.keyId(), KeyVersion.first(), SIGN, caller));
        assertNotNull(manager.publicKey(ed448.keyId(), KeyVersion.first(), VERIFY, caller));

        KeyDescriptor ec384 = generate(KeyType.EC, AlgorithmId.ECDSA_P384, 0, Set.of(SIGN));
        assertEquals(384, ec384.keyBits());
        assertEquals(Set.of(SIGN, VERIFY), ec384.usages());
        assertNotNull(manager.privateKey(ec384.keyId(), KeyVersion.first(), SIGN, caller));

        KeyDescriptor sm4 = generate(KeyType.SM4, AlgorithmId.SM4_GCM, 0, Set.of(ENCRYPT));
        assertEquals(128, sm4.keyBits());
        assertEquals("SM4", manager.secretKey(sm4.keyId(), KeyVersion.first(), ENCRYPT,
                caller).getAlgorithm());

        KeyDescriptor derive = generate(KeyType.AES, AlgorithmId.AES_GCM, 0, Set.of(DERIVE));
        assertEquals(derive.keyId(),
                manager.resolveForUse(derive.keyId(), null, DERIVE, caller).keyId());
        manager.deactivate(derive.keyId(), KeyVersion.first(), caller);
        KeyException deriveState = assertThrows(KeyException.class,
                () -> manager.resolveForUse(derive.keyId(), null, DERIVE, caller));
        assertEquals(ErrorCode.KEY_NOT_ACTIVE, deriveState.errorCode());

        KeyException sm2 = assertThrows(KeyException.class,
                () -> generate(KeyType.SM2, AlgorithmId.SM2, 0, Set.of(ENCRYPT)));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, sm2.errorCode());
        assertTrue(sm2.getMessage().contains("Bouncy Castle"));

        KeyException kem = assertThrows(KeyException.class,
                () -> generate(KeyType.KEM, AlgorithmId.ML_KEM_768, 0, Set.of(ENCRYPT)));
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, kem.errorCode());

        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, assertThrows(KeyException.class,
                () -> generate(KeyType.RSA, AlgorithmId.RSA_OAEP, 1024, Set.of(ENCRYPT)))
                .errorCode());
        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, assertThrows(KeyException.class,
                () -> generate(KeyType.HMAC, AlgorithmId.HMAC_SHA256, 128, Set.of(MAC)))
                .errorCode());
        assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, assertThrows(KeyException.class,
                () -> generate(KeyType.AES, AlgorithmId.AES_GCM, 64, Set.of(ENCRYPT)))
                .errorCode());
    }

    @Test
    void importsJwkPrivateAndSymmetricKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        String privateJwk = "{\"kty\":\"RSA\",\"n\":\"" + unsignedBase64(publicKey.getModulus())
                + "\",\"e\":\"" + unsignedBase64(publicKey.getPublicExponent())
                + "\",\"d\":\"" + unsignedBase64(privateKey.getPrivateExponent()) + "\"}";
        KeyId privateId = KeyId.of("jwk-rsa-private");
        KeyDescriptor privateDescriptor = manager.importKey(KeyImportRequest.builder(privateId,
                        ImportFormat.JWK, privateJwk.getBytes(StandardCharsets.UTF_8),
                        KeyType.RSA, AlgorithmId.RSA_PSS, Set.of(DECRYPT))
                .build(), caller);
        assertEquals(KeyState.PRE_ACTIVATION, privateDescriptor.state());
        assertEquals(KeyMaterialCodec.KEYPAIR,
                provider.load(privateId, KeyVersion.first()).orElseThrow().materialFormat());
        manager.activate(privateId, KeyVersion.first(), caller);
        RSAPrivateKey importedPrivate = (RSAPrivateKey) manager.privateKey(privateId,
                KeyVersion.first(), DECRYPT, caller);
        assertEquals(privateKey.getModulus(), importedPrivate.getModulus());
        assertEquals(privateKey.getPrivateExponent(), importedPrivate.getPrivateExponent());
        assertArrayEquals(pair.getPublic().getEncoded(),
                manager.publicKey(privateId, KeyVersion.first(), DECRYPT, caller).getEncoded());

        byte[] raw = new byte[16];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (0x60 + i);
        }
        String octJwk = "{\"kty\":\"oct\",\"k\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(raw) + "\"}";
        KeyId symmetricId = KeyId.of("jwk-oct");
        KeyDescriptor symmetric = manager.importKey(KeyImportRequest.builder(symmetricId,
                        ImportFormat.JWK, octJwk.getBytes(StandardCharsets.UTF_8), KeyType.AES,
                        AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                .build(), caller);
        assertEquals(128, symmetric.keyBits());
        manager.activate(symmetricId, KeyVersion.first(), caller);
        assertArrayEquals(raw, manager.secretKey(symmetricId, KeyVersion.first(), ENCRYPT,
                caller).getEncoded());
    }

    @Test
    void rejectsDuplicateKeysAndClosedManager() {
        KeyId keyId = KeyId.of("duplicate-key");
        manager.generate(KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                Set.of(ENCRYPT)).keyId(keyId).build(), caller);
        KeyException duplicate = assertThrows(KeyException.class, () -> manager.generate(
                KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT)).keyId(keyId).build(), caller));
        assertEquals(ErrorCode.KEY_ALREADY_EXISTS, duplicate.errorCode());

        manager.close();
        KeyException closed = assertThrows(KeyException.class,
                () -> manager.describe(keyId, KeyVersion.first(), caller));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, closed.errorCode());
        assertEquals(HealthStatus.DOWN, manager.health());
        manager.close();
    }

    @Test
    void peekForUseIsReadOnlyAndDoesNotRotateOrCountUsage() {
        KeyId keyId = KeyId.of("peek-key");
        manager.generate(KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .keyId(keyId)
                .rotationPolicy(new RotationPolicy(Duration.ofHours(1), 0, 3))
                .build(), caller);
        clock.advance(Duration.ofHours(2));
        long policyCalls = policy.requests().size();

        KeyDescriptor peeked = manager.peekForUse(keyId, null, ENCRYPT, caller);

        assertEquals(1, peeked.version().value());
        assertEquals(0, peeked.usageCount());
        assertEquals(policyCalls, policy.requests().size(),
                "peek must not evaluate the policy engine");
        assertEquals(1, manager.versions(keyId, caller).size(),
                "peek must not trigger lazy rotation");
        assertEquals(0, manager.describe(keyId, KeyVersion.first(), caller).orElseThrow()
                .usageCount());

        KeyDescriptor resolved = manager.resolveForUse(keyId, null, ENCRYPT, caller);
        assertEquals(2, resolved.version().value());
        assertEquals(1, resolved.usageCount());
    }

    @Test
    void resolveForUseDoesNotConsumePolicyEvaluations() {
        KeyDescriptor descriptor = generate(KeyType.AES, AlgorithmId.AES_GCM, 0,
                Set.of(ENCRYPT));
        long before = policy.requests().size();

        KeyDescriptor resolved = manager.resolveForUse(descriptor.keyId(), null, ENCRYPT, caller);

        assertEquals(1, resolved.usageCount());
        assertEquals(before, policy.requests().size(),
                "data-use resolution must not evaluate policy a second time");
    }

    @Test
    void singlePolicyEvaluationAllowsFacadeStylePeekAndResolve() {
        CountingPolicyEngine counting = new CountingPolicyEngine(1);
        InMemoryKeyProvider separateProvider = new InMemoryKeyProvider();
        DefaultKeyManager managed = new DefaultKeyManager(separateProvider, List.of(), counting,
                audit, clock);
        try {
            KeyDescriptor descriptor = managed.generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                    .build(), caller);
            counting.reset(1);

            KeyDescriptor peeked = managed.peekForUse(descriptor.keyId(), null, ENCRYPT, caller);
            PolicyDecision decision = counting.evaluate(PolicyRequest.builder(Operation.ENCRYPT,
                            caller)
                    .algorithm(peeked.algorithm())
                    .keyId(peeked.keyId())
                    .keyVersion(peeked.version())
                    .key(peeked)
                    .build());
            assertTrue(decision.allowed());
            KeyDescriptor resolved = managed.resolveForUse(descriptor.keyId(), null, ENCRYPT,
                    caller);

            assertEquals(1, resolved.usageCount());
            assertEquals(0, counting.remaining());
        } finally {
            managed.close();
        }
    }

    @Test
    void concurrentResolveForUseSurvivesLazyRotation() throws Exception {
        KeyId keyId = KeyId.of("concurrent-rotation");
        manager.generate(KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                        Set.of(ENCRYPT))
                .keyId(keyId)
                .rotationPolicy(new RotationPolicy(Duration.ofHours(1), 0, 5))
                .build(), caller);
        clock.advance(Duration.ofHours(2));

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<KeyDescriptor>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return manager.resolveForUse(keyId, null, ENCRYPT, caller);
                }));
            }
            start.countDown();
            for (Future<KeyDescriptor> future : futures) {
                KeyDescriptor descriptor = future.get(60, TimeUnit.SECONDS);
                assertEquals(2, descriptor.version().value());
                assertEquals(KeyState.ACTIVE, descriptor.state());
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(2, manager.versions(keyId, caller).size());
    }

    @Test
    void policyRequestsCarryDescriptorAndTargetTenant() {
        KeyDescriptor descriptor = manager.generate(KeyGenerationRequest.builder(KeyType.AES,
                        AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                .tenantId("default")
                .attributes(Map.of("team", "crypto"))
                .build(), caller);

        PolicyRequest generated = policy.requests().stream()
                .filter(request -> request.operation() == Operation.GENERATE_KEY)
                .findFirst().orElseThrow();
        assertEquals("default", generated.attributes().get("targetTenant"));
        assertEquals("crypto", generated.attributes().get("team"));

        manager.destroy(descriptor.keyId(), descriptor.version(), caller);
        PolicyRequest destroyed = policy.requests().stream()
                .filter(request -> request.operation() == Operation.DESTROY_KEY)
                .reduce((first, second) -> second).orElseThrow();
        assertEquals(descriptor, destroyed.key());
        assertEquals(descriptor.algorithm(), destroyed.algorithm());
        assertEquals(descriptor, destroyed.key());
    }

    @Test
    void exportPublicKeyRejectsSymmetricDescriptorWithX509Format() {
        KeyId keyId = KeyId.of("fake-x509-symmetric");
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (0x30 + i);
        }
        KeyDescriptor descriptor = KeyDescriptor.builder()
                .keyId(keyId)
                .version(KeyVersion.first())
                .type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM)
                .keyBits(256)
                .state(KeyState.ACTIVE)
                .usages(Set.of(ENCRYPT, DECRYPT))
                .tenantId("default")
                .createdAt(START)
                .activatedAt(START)
                .rotationPolicy(RotationPolicy.defaults())
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of())
                .fingerprint(KeySupport.fingerprint(secret))
                .build();
        provider.save(new StoredKey(descriptor, secret, KeyMaterialCodec.X509, false, Map.of()));

        KeyException denied = assertThrows(KeyException.class,
                () -> manager.exportPublicKey(keyId, KeyVersion.first(), caller));
        assertEquals(ErrorCode.KEY_EXPORT_DENIED, denied.errorCode());
        assertFalse(denied.getMessage().contains(Base64.getEncoder().encodeToString(secret)));
    }

    @Test
    void exportPublicKeyReturnsParsedEcPublicKey() throws Exception {
        KeyDescriptor descriptor = generate(KeyType.EC, AlgorithmId.ECDSA_P256, 0, Set.of(SIGN));

        byte[] exported = manager.exportPublicKey(descriptor.keyId(), KeyVersion.first(), caller);

        PublicKey parsed = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(exported));
        assertNotNull(parsed);
        assertArrayEquals(manager.publicKey(descriptor.keyId(), KeyVersion.first(), VERIFY,
                caller).getEncoded(), exported);
    }

    @Test
    void destroysFileBackedKeyAndKeepsStoreReadable(@TempDir Path tempDirectory) {
        char[] password = "file-master-password".toCharArray();
        FileKeyProvider fileProvider = new FileKeyProvider(tempDirectory, password);
        DefaultKeyManager fileManager = new DefaultKeyManager(fileProvider, List.of(), policy,
                audit, clock);
        KeyDescriptor first;
        KeyDescriptor second;
        try {
            first = fileManager.generate(KeyGenerationRequest.builder(KeyType.AES,
                    AlgorithmId.AES_GCM, Set.of(ENCRYPT)).build(), caller);
            second = fileManager.generate(KeyGenerationRequest.builder(KeyType.AES,
                    AlgorithmId.AES_GCM, Set.of(ENCRYPT)).build(), caller);

            assertEquals(KeyState.DESTROYED,
                    fileManager.destroy(first.keyId(), first.version(), caller).state());
            assertEquals(2, fileManager.list("default", caller).size());
            assertNotNull(fileManager.secretKey(second.keyId(), second.version(), ENCRYPT,
                    caller));
        } finally {
            fileManager.close();
        }

        FileKeyProvider reopenedProvider = new FileKeyProvider(tempDirectory, password);
        DefaultKeyManager reopened = new DefaultKeyManager(reopenedProvider, List.of(), policy,
                audit, clock);
        try {
            assertEquals(2, reopened.list("default", caller).size());
            assertEquals(KeyState.DESTROYED, reopened.describe(first.keyId(), first.version(),
                    caller).orElseThrow().state());
            assertNotNull(reopened.secretKey(second.keyId(), second.version(), ENCRYPT, caller));
        } finally {
            reopened.close();
        }
    }

    private KeyDescriptor generate(KeyType type, AlgorithmId algorithm, int bits,
                                   Set<KeyUsage> usages) {
        return manager.generate(KeyGenerationRequest.builder(type, algorithm, usages)
                .keyBits(bits)
                .build(), caller);
    }

    private static CallerContext caller(String tenantId, Set<String> roles) {
        return TestSupport.caller(tenantId, roles);
    }

    private static String unsignedBase64(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Policy engine that allows a fixed number of evaluations, then denies. */
    private static final class CountingPolicyEngine implements PolicyEngine {

        private final AtomicInteger remaining;

        private CountingPolicyEngine(int allowedEvaluations) {
            this.remaining = new AtomicInteger(allowedEvaluations);
        }

        void reset(int allowedEvaluations) {
            remaining.set(allowedEvaluations);
        }

        int remaining() {
            return remaining.get();
        }

        @Override
        public String engineId() {
            return "counting-policy";
        }

        @Override
        public PolicyDecision evaluate(PolicyRequest request) {
            if (remaining.getAndDecrement() <= 0) {
                return PolicyDecision.deny("RATE_LIMIT", "rate limit exceeded", engineId());
            }
            return PolicyDecision.allow(engineId());
        }

        @Override
        public HealthStatus health() {
            return HealthStatus.UP;
        }
    }
}