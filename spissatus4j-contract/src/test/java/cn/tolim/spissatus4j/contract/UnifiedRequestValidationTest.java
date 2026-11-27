package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.unified.AlgorithmSuite;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class UnifiedRequestValidationTest {

    private static final CallerContext CALLER =
            CallerContext.of("caller", "tenant", Set.of("crypto-user"));
    private static final KeyId KEY = KeyId.of("key-1");
    private static final byte[] PLAINTEXT = "hello".getBytes(StandardCharsets.UTF_8);

    @Test
    void keySelectionIsExclusiveAndNonEmpty() {
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder((KeyId) null, PLAINTEXT, CALLER).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(List.of(), PLAINTEXT, CALLER).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .candidateKeyIds(List.of(KeyId.of("key-2"))).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(List.of(KEY, KEY), PLAINTEXT, CALLER).build());
        assertDoesNotThrow(() -> UnifiedEncryptRequest.builder(List.of(KEY), PLAINTEXT, CALLER)
                .build());
        assertDoesNotThrow(() -> UnifiedEncryptRequest.builderAutoKey(PLAINTEXT, CALLER).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builderAutoKey(PLAINTEXT, CALLER)
                        .keyId(KEY).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builderAutoKey(PLAINTEXT, CALLER)
                        .candidateKeyIds(List.of(KEY)).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builderAutoKey(PLAINTEXT, CALLER)
                        .keyVersion(1L).build());
    }

    @Test
    void deactivatedEncryptionOptInDefaultsToFalse() {
        assertFalse(UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER).build()
                .allowDeactivatedKey());
        assertTrue(UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                .allowDeactivatedKey(true).build().allowDeactivatedKey());
    }

    @Test
    void selectionIntentIsMutuallyExclusive() {
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .algorithm(AlgorithmId.AES_GCM)
                        .suite(AlgorithmSuite.AEAD_AES_256_GCM).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .algorithm(AlgorithmId.AES_GCM)
                        .profile(SelectionProfile.AUTO_AEAD).build());
        assertDoesNotThrow(() -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                .profile(SelectionProfile.AUTO_AEAD).build());
    }

    @Test
    void reservedAttributesAndLimitsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .attributes(Map.of("spissatus.binding", "1")).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .attributes(Map.of("spi4.internal", "1")).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .aad(AAD.of(new byte[1_048_576])).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                        .attributes(Map.of("bad\uD800", "value")).build());
    }

    @Test
    void toStringNeverIncludesPlaintextOrAad() {
        String form = UnifiedEncryptRequest.builder(KEY, PLAINTEXT, CALLER)
                .aad(AAD.ofUtf8("sensitive-context"))
                .attributes(Map.of("label", "sensitive-attribute"))
                .build().toString();
        assertFalse(form.contains("hello"));
        assertFalse(form.contains("sensitive-context"));
        assertFalse(form.contains("sensitive-attribute"));
    }

    @Test
    void decryptRequestValidatesEncodingAndTimeWindow() {
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedDecryptRequest.builder(new byte[0], CALLER).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedDecryptRequest.builder("text", CALLER)
                        .encoding(cn.tolim.spissatus4j.contract.envelope.BinaryEncoding.RAW).build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedDecryptRequest.builder(new byte[]{1}, CALLER)
                        .encoding(cn.tolim.spissatus4j.contract.envelope.BinaryEncoding.BASE64)
                        .build());
        assertThrows(IllegalArgumentException.class,
                () -> UnifiedDecryptRequest.builder(new byte[]{1}, CALLER)
                        .maxAge(Duration.ZERO).build());
        UnifiedDecryptRequest request = UnifiedDecryptRequest.builder("secret-envelope-text", CALLER)
                .expectedAlgorithm(AlgorithmId.AES_GCM)
                .expectedKeyId(KEY)
                .expectedKeyVersion(1L)
                .expectedAad(AAD.ofUtf8("aad"))
                .expectedAttributes(Map.of("trace", "abc"))
                .maxAge(Duration.ofMinutes(1))
                .allowLegacyV1(true)
                .build();
        assertEquals(AlgorithmId.AES_GCM, request.expectedAlgorithm());
        assertTrue(request.allowLegacyV1());
        assertFalse(request.toString().contains("secret-envelope-text"));
    }
}