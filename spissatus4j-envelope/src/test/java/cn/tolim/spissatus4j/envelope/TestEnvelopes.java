package cn.tolim.spissatus4j.envelope;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.function.Executable;

final class TestEnvelopes {

    static final Instant CREATED_AT = Instant.parse("2026-01-02T03:04:05.123Z");

    private TestEnvelopes() {
    }

    static byte[] bytes(int length, int seed) {
        byte[] value = new byte[length];
        for (int index = 0; index < length; index++) {
            value[index] = (byte) ((index + seed) & 0xFF);
        }
        return value;
    }

    static KdfParameters.Argon2id lowCostArgon2id() {
        return new KdfParameters.Argon2id(1024, 2, 1, 32, 19);
    }

    static Envelope aesGcmEnvelope() {
        return aesGcmEnvelopeBuilder().build();
    }

    static Envelope.Builder aesGcmEnvelopeBuilder() {
        return Envelope.builder()
                .version(1)
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key-1"))
                .keyVersion(KeyVersion.of(2))
                .nonce(Nonce.of(bytes(12, 1)))
                .salt(Salt.of(bytes(16, 2)))
                .kdfParameters(lowCostArgon2id())
                .aad(AAD.ofUtf8("aad-context"))
                .ciphertext(bytes(32, 3))
                .tag(bytes(16, 4))
                .createdAt(CREATED_AT)
                .format(EnvelopeFormat.TLV)
                .binaryEncoding(BinaryEncoding.RAW)
                .attributes(Map.of("purpose", "unit-test", "tenant", "acme"));
    }

    static Envelope simpleAesGcmEnvelope() {
        return Envelope.builder()
                .version(1)
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key-1"))
                .keyVersion(KeyVersion.first())
                .nonce(Nonce.of(bytes(12, 7)))
                .ciphertext(bytes(24, 8))
                .tag(bytes(16, 9))
                .createdAt(CREATED_AT)
                .format(EnvelopeFormat.TLV)
                .binaryEncoding(BinaryEncoding.RAW)
                .attributes(Map.of("a", "b"))
                .build();
    }

    static void assertSameContents(Envelope expected, Envelope actual) {
        assertEquals(expected.version(), actual.version());
        assertEquals(expected.algorithm(), actual.algorithm());
        assertEquals(expected.keyId(), actual.keyId());
        assertEquals(expected.keyVersion(), actual.keyVersion());
        assertArrayEquals(expected.nonce().asBytes(), actual.nonce().asBytes());
        assertArrayEquals(expected.salt().asBytes(), actual.salt().asBytes());
        assertArrayEquals(expected.aad().asBytes(), actual.aad().asBytes());
        assertArrayEquals(expected.ciphertext(), actual.ciphertext());
        assertArrayEquals(expected.tag(), actual.tag());
        assertEquals(expected.createdAt(), actual.createdAt());
        assertEquals(expected.attributes(), actual.attributes());
        if (expected.kdfParameters() == null) {
            assertNull(actual.kdfParameters());
        } else {
            assertEquals(expected.kdfParameters().toMap(), actual.kdfParameters().toMap());
        }
    }

    static void assertErrorCode(ErrorCode expected, Executable executable) {
        EnvelopeException exception = org.junit.jupiter.api.Assertions.assertThrows(
                EnvelopeException.class, executable);
        assertEquals(expected, exception.errorCode());
    }
}