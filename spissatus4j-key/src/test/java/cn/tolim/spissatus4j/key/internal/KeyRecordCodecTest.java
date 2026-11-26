package cn.tolim.spissatus4j.key.internal;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.RotationPolicy;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class KeyRecordCodecTest {

    private static final Instant CREATED = Instant.parse("2026-06-01T00:00:00Z");

    @Test
    void decodesTombstonesWithEmptyMaterial() {
        byte[] encoded = KeyRecordCodec.encodeStoredKey(storedKey(KeyState.DESTROYED, new byte[0]));

        StoredKey decoded = KeyRecordCodec.decodeStoredKey(encoded);

        assertEquals(KeyState.DESTROYED, decoded.descriptor().state());
        assertEquals(0, decoded.material().length);
        assertEquals(KeyMaterialCodec.RAW, decoded.materialFormat());
    }

    @Test
    void rejectsEmptyMaterialForNonTerminalRecords() {
        byte[] encoded = KeyRecordCodec.encodeStoredKey(storedKey(KeyState.ACTIVE, new byte[0]));

        KeyException exception = assertThrows(KeyException.class,
                () -> KeyRecordCodec.decodeStoredKey(encoded));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, exception.errorCode());
    }

    @Test
    void rejectsOversizedMaterialBeforeEncoding() {
        byte[] huge = new byte[KeyRecordCodec.MAX_MATERIAL_BYTES + 1];

        KeyException exception = assertThrows(KeyException.class,
                () -> KeyRecordCodec.encodeStoredKey(descriptor(KeyState.ACTIVE, 0), huge,
                        KeyMaterialCodec.RAW, false, Map.of()));
        assertEquals(ErrorCode.INVALID_PARAMETER, exception.errorCode());
    }

    private static StoredKey storedKey(KeyState state, byte[] material) {
        return new StoredKey(descriptor(state, material.length * 8), material,
                KeyMaterialCodec.RAW, false, Map.of());
    }

    private static KeyDescriptor descriptor(KeyState state, int keyBits) {
        return KeyDescriptor.builder()
                .keyId(KeyId.of("codec-key"))
                .version(KeyVersion.first())
                .type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM)
                .keyBits(keyBits)
                .state(state)
                .usages(Set.of(ENCRYPT, DECRYPT))
                .tenantId("default")
                .createdAt(CREATED)
                .activatedAt(CREATED)
                .rotationPolicy(RotationPolicy.defaults())
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of())
                .fingerprint(null)
                .build();
    }
}
