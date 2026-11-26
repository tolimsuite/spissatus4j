package cn.tolim.spissatus4j.key.manager;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.provider.InMemoryKeyProvider;
import cn.tolim.spissatus4j.key.support.TestSupport;
import cn.tolim.spissatus4j.key.support.TestSupport.MutableClock;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingAuditTrail;
import cn.tolim.spissatus4j.key.support.TestSupport.StubPolicyEngine;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ChaCha20KeyGenerationTest {

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
    void generatesChaCha20Poly1305KeyWithDefaultSize() {
        KeyDescriptor descriptor = manager.generate(KeyGenerationRequest.builder(
                        KeyType.SYMMETRIC, AlgorithmId.CHACHA20_POLY1305,
                        Set.of(ENCRYPT, DECRYPT))
                .build(), caller);

        assertEquals(KeyType.SYMMETRIC, descriptor.type());
        assertEquals(AlgorithmId.CHACHA20_POLY1305, descriptor.algorithm());
        assertEquals(256, descriptor.keyBits());
        assertEquals(KeyState.ACTIVE, descriptor.state());
        assertEquals(Set.of(ENCRYPT, DECRYPT), descriptor.usages());

        byte[] storedMaterial = provider.load(descriptor.keyId(), KeyVersion.first())
                .orElseThrow().material();
        assertEquals(KeyMaterialCodec.RAW,
                provider.load(descriptor.keyId(), KeyVersion.first())
                        .orElseThrow().materialFormat());
        assertEquals(32, storedMaterial.length);

        SecretKey secretKey = manager.secretKey(descriptor.keyId(), KeyVersion.first(),
                ENCRYPT, caller);
        assertEquals("ChaCha20", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length);
        assertArrayEquals(storedMaterial, secretKey.getEncoded());
        assertEquals(32, manager.secretKey(descriptor.keyId(), KeyVersion.first(), DECRYPT,
                caller).getEncoded().length);
    }

    @Test
    void acceptsExplicit256BitChaCha20Poly1305Key() {
        KeyDescriptor descriptor = manager.generate(KeyGenerationRequest.builder(
                        KeyType.SYMMETRIC, AlgorithmId.CHACHA20_POLY1305,
                        Set.of(ENCRYPT, DECRYPT))
                .keyBits(256)
                .build(), caller);

        assertEquals(256, descriptor.keyBits());
        assertEquals(32, manager.secretKey(descriptor.keyId(), KeyVersion.first(), ENCRYPT,
                caller).getEncoded().length);
    }

    @Test
    void rejectsNon256BitChaCha20Poly1305Keys() {
        for (int bits : new int[]{128, 512}) {
            KeyException failure = assertThrows(KeyException.class,
                    () -> manager.generate(KeyGenerationRequest.builder(KeyType.SYMMETRIC,
                                    AlgorithmId.CHACHA20_POLY1305, Set.of(ENCRYPT, DECRYPT))
                            .keyBits(bits)
                            .build(), caller));
            assertEquals(ErrorCode.MIN_KEY_BITS_VIOLATION, failure.errorCode());
            assertEquals("ChaCha20-Poly1305 keys must be 256 bits", failure.getMessage());
        }
        assertTrue(provider.list(null).isEmpty(),
                "rejected key sizes must not persist key material");
    }
}
