package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeBinding;
import cn.tolim.spissatus4j.contract.key.KeyId;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EnvelopeBindingTest {

    private static final Instant CREATED = Instant.ofEpochMilli(1_700_000_000_000L);
    private static final KeyId KEY = KeyId.of("key-1");
    private static final Map<String, String> ATTRIBUTES = Map.of("trace", "abc");

    @Test
    void knownVectorIsStable() {
        String actual = HexFormat.of().formatHex(EnvelopeBinding.headerHash(
                2, AlgorithmId.AES_GCM, KEY, CREATED, Salt.empty(), null, ATTRIBUTES));
        assertEquals("1bf7e585783443c5a781868a61c8a6c4cc404a562595c61886a734e38fe17eb2",
                actual);
    }

    @Test
    void attributeOrderDoesNotChangeTheHash() {
        Map<String, String> first = new LinkedHashMap<>();
        first.put("a", "1");
        first.put("b", "2");
        Map<String, String> second = new LinkedHashMap<>();
        second.put("b", "2");
        second.put("a", "1");
        assertEquals(HexFormat.of().formatHex(EnvelopeBinding.headerHash(2,
                        AlgorithmId.AES_GCM, KEY, CREATED, Salt.empty(), null, first)),
                HexFormat.of().formatHex(EnvelopeBinding.headerHash(2,
                        AlgorithmId.AES_GCM, KEY, CREATED, Salt.empty(), null, second)));
    }

    @Test
    void everyBoundFieldChangesTheHash() {
        byte[] baseline = EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY, CREATED,
                Salt.empty(), null, ATTRIBUTES);
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(3, AlgorithmId.AES_GCM, KEY, CREATED,
                        Salt.empty(), null, ATTRIBUTES)));
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(2, AlgorithmId.CHACHA20_POLY1305, KEY, CREATED,
                        Salt.empty(), null, ATTRIBUTES)));
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KeyId.of("key-2"), CREATED,
                        Salt.empty(), null, ATTRIBUTES)));
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY,
                        CREATED.plusMillis(1), Salt.empty(), null, ATTRIBUTES)));
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY, CREATED,
                        Salt.of(new byte[]{1}), null, ATTRIBUTES)));
        assertNotEquals(HexFormat.of().formatHex(baseline), HexFormat.of().formatHex(
                EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY, CREATED,
                        Salt.empty(), null, Map.of("trace", "def"))));
    }

    @Test
    void effectiveAadIsDomainSeparatedAndBoundToTheHeader() {
        byte[] first = EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY, CREATED,
                Salt.empty(), null, ATTRIBUTES);
        byte[] second = EnvelopeBinding.headerHash(2, AlgorithmId.AES_GCM, KEY,
                CREATED.plusMillis(1), Salt.empty(), null, ATTRIBUTES);
        AAD userAad = AAD.ofUtf8("context");
        AAD aad = EnvelopeBinding.effectiveAad(userAad, first);
        assertFalse(aad.isEmpty());
        assertTrue(aad.length() > userAad.length());
        assertNotEquals(aad, EnvelopeBinding.effectiveAad(userAad, second));
        assertNotEquals(aad, EnvelopeBinding.effectiveAad(AAD.ofUtf8("other"), first));
    }
}