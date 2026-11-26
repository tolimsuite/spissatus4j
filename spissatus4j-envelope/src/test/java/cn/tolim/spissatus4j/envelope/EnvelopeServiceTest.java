package cn.tolim.spissatus4j.envelope;

import static cn.tolim.spissatus4j.envelope.TestEnvelopes.CREATED_AT;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.aesGcmEnvelope;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.aesGcmEnvelopeBuilder;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertErrorCode;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertSameContents;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.bytes;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.v2AesGcmEnvelope;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.v2AesGcmEnvelopeBuilder;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.envelope.codec.JsonEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.codec.TlvEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.internal.DefaultEnvelopeService;
import cn.tolim.spissatus4j.envelope.internal.DefaultVersionPolicy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class EnvelopeServiceTest {

    private final DefaultEnvelopeService service = new DefaultEnvelopeService();

    @Test
    void tlvRoundTripPreservesAllAesGcmFields() {
        Envelope original = aesGcmEnvelope();
        byte[] encoded = service.encode(original, EnvelopeFormat.TLV);
        Envelope decoded = service.decode(encoded);
        assertSameContents(original, decoded);
        assertEquals(EnvelopeFormat.TLV, decoded.format());
        assertEquals(BinaryEncoding.RAW, decoded.binaryEncoding());
        assertNotNull(decoded.kdfParameters());
        assertEquals(original.kdfParameters().toMap(), decoded.kdfParameters().toMap());
    }

    @Test
    void jsonRoundTripPreservesAllAesGcmFields() {
        Envelope original = aesGcmEnvelope();
        byte[] encoded = service.encode(original, EnvelopeFormat.JSON);
        String json = new String(encoded, StandardCharsets.UTF_8);
        assertTrue(json.startsWith("{"));
        Envelope decoded = service.decode(encoded);
        assertSameContents(original, decoded);
        assertEquals(EnvelopeFormat.JSON, decoded.format());
        assertEquals(BinaryEncoding.RAW, decoded.binaryEncoding());
        assertEquals(original.kdfParameters().toMap(), decoded.kdfParameters().toMap());
    }

    @Test
    void crossFormatReEncodingPreservesSemantics() {
        Envelope original = aesGcmEnvelope();
        Envelope tlvDecoded = service.decode(service.encode(original, EnvelopeFormat.TLV));
        byte[] jsonBytes = service.encode(tlvDecoded, EnvelopeFormat.JSON);
        Envelope jsonDecoded = service.decode(jsonBytes);
        assertSameContents(original, jsonDecoded);
        assertEquals(EnvelopeFormat.JSON, jsonDecoded.format());

        byte[] tlvBytes = service.encode(jsonDecoded, EnvelopeFormat.TLV);
        Envelope secondTlvDecoded = service.decode(tlvBytes);
        assertSameContents(original, secondTlvDecoded);
        assertEquals(EnvelopeFormat.TLV, secondTlvDecoded.format());
    }

    @Test
    void textEncodingsRoundTripForBothFormats() {
        Envelope original = aesGcmEnvelope();
        for (EnvelopeFormat format : EnvelopeFormat.values()) {
            for (BinaryEncoding encoding : List.of(
                    BinaryEncoding.BASE64, BinaryEncoding.BASE64URL, BinaryEncoding.HEX)) {
                String text = service.encodeText(original, format, encoding);
                assertFalse(text.isEmpty());
                Envelope decoded = service.decodeText(text);
                assertSameContents(original, decoded);
                assertEquals(format, decoded.format());
                assertEquals(BinaryEncoding.RAW, decoded.binaryEncoding());
                if (encoding == BinaryEncoding.BASE64URL) {
                    assertFalse(text.contains("="), "base64url must be emitted without padding");
                }
                if (encoding == BinaryEncoding.HEX) {
                    assertTrue(text.matches("[0-9a-f]+"), "hex must be lowercase");
                }
            }
        }
    }

    @Test
    void base64UrlWithoutPaddingIsAccepted() {
        byte[] encoded = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        String unpadded = Base64.getEncoder().encodeToString(encoded)
                .replace('+', '-').replace('/', '_').replace("=", "");
        assertFalse(unpadded.contains("="));
        assertSameContents(aesGcmEnvelope(), service.decodeText(unpadded));

        String padded = Base64.getUrlEncoder().encodeToString(encoded);
        assertSameContents(aesGcmEnvelope(), service.decodeText(padded));
    }

    @Test
    void tamperedEnvelopesAreRejected() {
        byte[] tlv = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] tamperedTlv = tlv.clone();
        tamperedTlv[0] ^= 0x01;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(tamperedTlv));

        byte[] json = service.encode(aesGcmEnvelope(), EnvelopeFormat.JSON);
        byte[] tamperedJson = json.clone();
        tamperedJson[0] = (byte) '[';
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(tamperedJson));
    }

    @Test
    void truncatedTlvIsRejected() {
        byte[] tlv = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] truncatedTail = Arrays.copyOf(tlv, tlv.length - 1);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(truncatedTail));
        byte[] truncatedHead = Arrays.copyOf(tlv, 10);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(truncatedHead));
    }

    @Test
    void trailingBytesAreRejected() {
        byte[] tlv = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] withTrailing = Arrays.copyOf(tlv, tlv.length + 1);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(withTrailing));

        byte[] json = service.encode(aesGcmEnvelope(), EnvelopeFormat.JSON);
        byte[] jsonWithTrailing = new byte[json.length + 2];
        System.arraycopy(json, 0, jsonWithTrailing, 0, json.length);
        jsonWithTrailing[json.length] = '{';
        jsonWithTrailing[json.length + 1] = '}';
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(jsonWithTrailing));
    }

    @Test
    void unsupportedVersionThreeIsRejectedOnEncodeAndDecode() {
        Envelope versionThree = v2AesGcmEnvelopeBuilder().version(3).build();
        assertErrorCode(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                () -> service.encode(versionThree, EnvelopeFormat.TLV));

        byte[] tlv = service.encode(v2AesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] patched = tlv.clone();
        patched[8] = 0;
        patched[9] = 3;
        assertErrorCode(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION, () -> service.decode(patched));

        String json = new String(service.encode(v2AesGcmEnvelope(), EnvelopeFormat.JSON),
                StandardCharsets.UTF_8);
        String versionThreeJson = json.replace("\"version\":2", "\"version\":3");
        assertNotEquals(json, versionThreeJson);
        assertErrorCode(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                () -> service.decode(versionThreeJson.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void versionTwoRoundTripsThroughBothFormats() {
        Envelope original = v2AesGcmEnvelope();
        for (EnvelopeFormat format : EnvelopeFormat.values()) {
            Envelope decoded = service.decode(service.encode(original, format));
            assertSameContents(original, decoded);
            assertEquals(2, decoded.version());
            assertArrayEquals(original.headerHash(), decoded.headerHash());
            assertEquals(format, decoded.format());
        }
    }

    @Test
    void versionTwoEncodeAddsOneHeaderHashEntry() {
        byte[] versionOne = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] versionTwo = service.encode(v2AesGcmEnvelope(), EnvelopeFormat.TLV);
        assertEquals(versionOne.length + 6 + 32, versionTwo.length);

        int cap = versionOne.length + 20;
        DefaultEnvelopeService bounded = new DefaultEnvelopeService(
                List.of(new TlvEnvelopeCodec(cap), new JsonEnvelopeCodec(cap)),
                new DefaultVersionPolicy(), cap);
        assertDoesNotThrow(() -> bounded.encode(aesGcmEnvelope(), EnvelopeFormat.TLV));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> bounded.encode(v2AesGcmEnvelope(), EnvelopeFormat.TLV));
    }

    @Test
    void createBoundBuildsVersionTwoEnvelopeBoundToHeaderHash() {
        EncryptedData data = EncryptedData.builder()
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key-9"))
                .keyVersion(KeyVersion.of(3))
                .nonce(Nonce.of(bytes(12, 5)))
                .ciphertext(bytes(20, 6))
                .tag(bytes(16, 7))
                .aad(AAD.ofUtf8("context"))
                .createdAt(CREATED_AT)
                .build();
        byte[] headerHash = bytes(32, 12);
        Envelope created = service.createBound(data, headerHash, Map.of("env", "bound"));
        headerHash[0] ^= 0x7F;

        assertEquals(2, created.version());
        assertEquals(EnvelopeFormat.JSON, created.format());
        assertEquals(BinaryEncoding.BASE64, created.binaryEncoding());
        assertEquals(data.algorithm(), created.algorithm());
        assertEquals(data.keyId(), created.keyId());
        assertEquals(data.keyVersion(), created.keyVersion());
        assertArrayEquals(data.nonce().asBytes(), created.nonce().asBytes());
        assertArrayEquals(data.ciphertext(), created.ciphertext());
        assertArrayEquals(data.tag(), created.tag());
        assertArrayEquals(data.aad().asBytes(), created.aad().asBytes());
        assertEquals(data.createdAt(), created.createdAt());
        assertEquals(Map.of("env", "bound"), created.attributes());
        assertArrayEquals(bytes(32, 12), created.headerHash(), "header hash must be cloned");
        assertDoesNotThrow(() -> service.validate(created));

        Envelope decoded = service.decode(service.encode(created, EnvelopeFormat.JSON));
        assertArrayEquals(bytes(32, 12), decoded.headerHash());
        assertSameContents(created, decoded);
    }

    @Test
    void createBoundRejectsMissingOrWrongLengthHeaderHash() {
        EncryptedData data = EncryptedData.builder()
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key-9"))
                .keyVersion(KeyVersion.first())
                .nonce(Nonce.of(bytes(12, 5)))
                .ciphertext(bytes(20, 6))
                .tag(bytes(16, 7))
                .createdAt(CREATED_AT)
                .build();
        assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> service.createBound(data, null, Map.of()));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.createBound(data, new byte[31], Map.of()));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.createBound(data, new byte[33], Map.of()));
    }

    @Test
    void versionTwoRequiresExactlyThirtyTwoHeaderHashBytes() {
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.validate(v2AesGcmEnvelopeBuilder().headerHash(new byte[0]).build()));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.validate(v2AesGcmEnvelopeBuilder().headerHash(bytes(31, 1)).build()));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.validate(v2AesGcmEnvelopeBuilder().headerHash(bytes(33, 1)).build()));

        Envelope versionOneWithHash = aesGcmEnvelopeBuilder().headerHash(bytes(32, 1)).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.validate(versionOneWithHash));
        assertDoesNotThrow(() -> service.validate(aesGcmEnvelope()));
    }

    @Test
    void versionTwoRejectsNonEncryptionAlgorithmFamilies() {
        Envelope hash = v2AesGcmEnvelopeBuilder().algorithm(AlgorithmId.SHA_256)
                .nonce(Nonce.empty())
                .tag(new byte[0])
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(hash));

        Envelope mac = v2AesGcmEnvelopeBuilder().algorithm(AlgorithmId.HMAC_SHA256)
                .nonce(Nonce.empty())
                .tag(bytes(32, 1))
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(mac));

        Envelope kem = v2AesGcmEnvelopeBuilder().algorithm(AlgorithmId.ML_KEM_768)
                .nonce(Nonce.empty())
                .tag(new byte[0])
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(kem));

        Envelope symmetric = v2AesGcmEnvelopeBuilder().algorithm(AlgorithmId.AES_CBC)
                .nonce(Nonce.of(bytes(16, 1)))
                .tag(bytes(32, 1))
                .build();
        assertDoesNotThrow(() -> service.validate(symmetric));

        Envelope asymmetric = v2AesGcmEnvelopeBuilder().algorithm(AlgorithmId.RSA_OAEP)
                .nonce(Nonce.empty())
                .tag(new byte[0])
                .build();
        assertDoesNotThrow(() -> service.validate(asymmetric));

        Envelope legacyHash = aesGcmEnvelopeBuilder().algorithm(AlgorithmId.SHA_256)
                .nonce(Nonce.empty())
                .tag(new byte[0])
                .build();
        assertDoesNotThrow(() -> service.validate(legacyHash),
                "version 1 validation must remain unchanged");
    }

    @Test
    void versionTwoRejectsReservedAttributePrefixes() {
        for (String reserved : List.of("spissatus.origin", "spi4.origin", "spissatus.a", "spi4.a")) {
            Envelope envelope = v2AesGcmEnvelopeBuilder()
                    .attributes(Map.of(reserved, "value"))
                    .build();
            assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    () -> service.validate(envelope));
        }

        Envelope versionOneReserved = aesGcmEnvelopeBuilder()
                .attributes(Map.of("spissatus.origin", "value"))
                .build();
        assertDoesNotThrow(() -> service.validate(versionOneReserved),
                "version 1 validation must remain unchanged");

        Envelope similarKeys = v2AesGcmEnvelopeBuilder()
                .attributes(Map.of("spissatus", "v", "spi4x", "v", "xspissatus.a", "v"))
                .build();
        assertDoesNotThrow(() -> service.validate(similarKeys));
    }

    @Test
    void decodedVersionTwoEnvelopesWithWrongHeaderHashLengthAreRejected() {
        Envelope tooShort = v2AesGcmEnvelopeBuilder().headerHash(bytes(31, 1)).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.decode(new JsonEnvelopeCodec().encode(tooShort)));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(new TlvEnvelopeCodec().encode(tooShort)));

        Envelope tooLong = v2AesGcmEnvelopeBuilder().headerHash(bytes(33, 1)).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.decode(new JsonEnvelopeCodec().encode(tooLong)));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(new TlvEnvelopeCodec().encode(tooLong)));
    }

    @Test
    void versionTwoTamperedMetadataFailsStructuralChecks() {
        byte[] json = service.encode(v2AesGcmEnvelope(), EnvelopeFormat.JSON);
        String text = new String(json, StandardCharsets.UTF_8);
        String downgraded = text.replace("\"version\":2", "\"version\":1");
        assertNotEquals(text, downgraded);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(downgraded.getBytes(StandardCharsets.UTF_8)));

        String withoutHash = text.replaceAll("\"headerHash\":\"[^\"]*\",", "");
        assertNotEquals(text, withoutHash);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(withoutHash.getBytes(StandardCharsets.UTF_8)));

        byte[] tlv = service.encode(v2AesGcmEnvelope(), EnvelopeFormat.TLV);
        byte[] versionOne = tlv.clone();
        versionOne[8] = 0;
        versionOne[9] = 1;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(versionOne));

        byte[] versionTwoWithoutHash = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        versionTwoWithoutHash[8] = 0;
        versionTwoWithoutHash[9] = 2;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(versionTwoWithoutHash));
    }

    @Test
    void unknownAlgorithmIsRejectedByValidateAndEncode() {
        Envelope unknown = Envelope.builder()
                .version(1)
                .algorithm(AlgorithmId.of("MYSTERY-ALG"))
                .keyId(KeyId.of("key-1"))
                .keyVersion(KeyVersion.first())
                .createdAt(CREATED_AT)
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(unknown));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> service.encode(unknown, EnvelopeFormat.TLV));
    }

    @Test
    void nonceAndTagLengthMismatchesAreRejected() {
        Envelope shortNonce = aesGcmEnvelopeBuilder().nonce(Nonce.of(bytes(8, 1))).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(shortNonce));

        Envelope shortTag = aesGcmEnvelopeBuilder().tag(bytes(12, 4)).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(shortTag));

        Envelope longNonce = aesGcmEnvelopeBuilder().nonce(Nonce.of(bytes(16, 1))).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(longNonce));
    }

    @Test
    void attributeBoundsAreEnforced() {
        Map<String, String> many = new HashMap<>();
        for (int index = 0; index < 65; index++) {
            many.put("key-" + index, "value");
        }
        Envelope tooMany = aesGcmEnvelopeBuilder().attributes(many).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(tooMany));

        Envelope longKey = aesGcmEnvelopeBuilder()
                .attributes(Map.of("k".repeat(129), "value"))
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(longKey));

        Envelope longValue = aesGcmEnvelopeBuilder()
                .attributes(Map.of("key", "v".repeat(4097)))
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(longValue));

        Envelope maxKey = aesGcmEnvelopeBuilder()
                .attributes(Map.of("k".repeat(128), "v".repeat(4096)))
                .build();
        assertDoesNotThrow(() -> service.validate(maxKey));
    }

    @Test
    void kdfMetadataRequiresNonEmptySalt() {
        Envelope noSalt = aesGcmEnvelopeBuilder().salt(Salt.empty()).build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> service.validate(noSalt));
    }

    @Test
    void emptyCiphertextAndAsymmetricEmptyNonceTagAreAllowed() {
        Envelope emptyCiphertext = aesGcmEnvelopeBuilder().ciphertext(new byte[0]).build();
        assertDoesNotThrow(() -> service.validate(emptyCiphertext));

        Envelope asymmetric = Envelope.builder()
                .version(1)
                .algorithm(AlgorithmId.RSA_OAEP)
                .keyId(KeyId.of("rsa-key"))
                .keyVersion(KeyVersion.first())
                .nonce(Nonce.empty())
                .ciphertext(bytes(256, 11))
                .tag(new byte[0])
                .createdAt(CREATED_AT)
                .build();
        assertDoesNotThrow(() -> service.validate(asymmetric));
        Envelope decoded = service.decode(service.encode(asymmetric, EnvelopeFormat.TLV));
        assertSameContents(asymmetric, decoded);
    }

    @Test
    void createBuildsVersionOneJsonEnvelope() {
        EncryptedData data = EncryptedData.builder()
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key-9"))
                .keyVersion(KeyVersion.of(3))
                .nonce(Nonce.of(bytes(12, 5)))
                .ciphertext(bytes(20, 6))
                .tag(bytes(16, 7))
                .aad(AAD.ofUtf8("context"))
                .createdAt(CREATED_AT)
                .build();
        Envelope created = service.create(data, Map.of("env", "test"));
        assertEquals(1, created.version());
        assertEquals(EnvelopeFormat.JSON, created.format());
        assertEquals(BinaryEncoding.BASE64, created.binaryEncoding());
        assertEquals(data.algorithm(), created.algorithm());
        assertEquals(data.keyId(), created.keyId());
        assertEquals(data.keyVersion(), created.keyVersion());
        assertArrayEquals(data.nonce().asBytes(), created.nonce().asBytes());
        assertArrayEquals(data.ciphertext(), created.ciphertext());
        assertArrayEquals(data.tag(), created.tag());
        assertArrayEquals(data.aad().asBytes(), created.aad().asBytes());
        assertEquals(data.createdAt(), created.createdAt());
        assertEquals(Map.of("env", "test"), created.attributes());
        assertDoesNotThrow(() -> service.validate(created));

        Envelope decoded = service.decode(service.encode(created, EnvelopeFormat.JSON));
        assertSameContents(created, decoded);
    }

    @Test
    void rawTextEncodingIsRejected() {
        assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> service.encodeText(aesGcmEnvelope(), EnvelopeFormat.TLV, BinaryEncoding.RAW));
    }

    @Test
    void malformedTextIsRejected() {
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decodeText(""));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decodeText("!!!!"));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decodeText("AAAA"));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decodeText("  "));
    }

    @Test
    void utf8BomJsonIsAcceptedButUtf16IsRejected() {
        byte[] encoded = service.encode(aesGcmEnvelope(), EnvelopeFormat.JSON);
        byte[] withBom = new byte[encoded.length + 3];
        withBom[0] = (byte) 0xEF;
        withBom[1] = (byte) 0xBB;
        withBom[2] = (byte) 0xBF;
        System.arraycopy(encoded, 0, withBom, 3, encoded.length);
        assertSameContents(aesGcmEnvelope(), service.decode(withBom));

        String text = new String(encoded, StandardCharsets.UTF_8);
        byte[] utf16leBody = text.getBytes(StandardCharsets.UTF_16LE);
        byte[] utf16le = new byte[2 + utf16leBody.length];
        utf16le[0] = (byte) 0xFF;
        utf16le[1] = (byte) 0xFE;
        System.arraycopy(utf16leBody, 0, utf16le, 2, utf16leBody.length);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> service.decode(utf16le));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> service.decode(text.getBytes(StandardCharsets.UTF_16BE)));
    }

    @Test
    void decodeTextRejectsBase64DecodedSizeAboveMaximumBeforeDecoding() {
        int maxBytes = 64;
        DefaultEnvelopeService bounded = new DefaultEnvelopeService(
                List.of(new TlvEnvelopeCodec(maxBytes), new JsonEnvelopeCodec(maxBytes)),
                new DefaultVersionPolicy(), maxBytes);
        byte[] overCap = bytes(maxBytes + 1, 3);

        String base64 = Base64.getEncoder().encodeToString(overCap);
        assertTrue(base64.length() <= 4L * maxBytes + 16L,
                "the encoded text must stay under the pre-decode length cap");
        EnvelopeException base64Failure = assertThrows(EnvelopeException.class,
                () -> bounded.decodeText(base64));
        assertEquals(ErrorCode.ENVELOPE_MALFORMED, base64Failure.errorCode());
        assertTrue(base64Failure.getMessage().contains("decoded size"),
                "the decoded-size guard must run before Base64 decoding: " + base64Failure.getMessage());

        String hex = HexFormat.of().formatHex(overCap);
        assertTrue(hex.length() <= 4L * maxBytes + 16L);
        EnvelopeException hexFailure = assertThrows(EnvelopeException.class,
                () -> bounded.decodeText(hex));
        assertEquals(ErrorCode.ENVELOPE_MALFORMED, hexFailure.errorCode());
        assertTrue(hexFailure.getMessage().contains("decoded size"),
                "the decoded-size guard must run before hex decoding: " + hexFailure.getMessage());
    }

    @Test
    void configuredMaximumSizeIsEnforced() {
        DefaultEnvelopeService bounded = new DefaultEnvelopeService(
                List.of(new TlvEnvelopeCodec(), new JsonEnvelopeCodec()),
                new DefaultVersionPolicy(), 64);
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> bounded.encode(aesGcmEnvelope(), EnvelopeFormat.TLV));

        byte[] encoded = service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> bounded.decode(encoded));
        assertTrue(encoded.length > 64);
    }

    @Test
    void fuzzRandomInputsFailClosed() {
        SplittableRandom random = new SplittableRandom(0x5EEDL);
        for (int iteration = 0; iteration < 2000; iteration++) {
            int length = random.nextInt(2049);
            byte[] input = new byte[length];
            for (int index = 0; index < length; index++) {
                input[index] = (byte) random.nextInt(256);
            }
            try {
                service.decode(input);
            } catch (EnvelopeException expected) {
                // fail-closed
            } catch (IllegalArgumentException allowed) {
                // the contract only forbids broad runtime failures
            } catch (RuntimeException e) {
                fail("Unexpected exception type for fuzz input of length " + length, e);
            }
        }
    }

    @Test
    void tlvMagicPrefixedFuzzInputsFailClosed() {
        byte[] magic = "SPI4ENV1".getBytes(StandardCharsets.US_ASCII);
        SplittableRandom random = new SplittableRandom(0xBEEFL);
        for (int iteration = 0; iteration < 1000; iteration++) {
            int length = 8 + random.nextInt(512);
            byte[] input = new byte[length];
            System.arraycopy(magic, 0, input, 0, magic.length);
            for (int index = magic.length; index < length; index++) {
                input[index] = (byte) random.nextInt(256);
            }
            try {
                service.decode(input);
            } catch (EnvelopeException expected) {
                // fail-closed
            } catch (RuntimeException e) {
                fail("Unexpected exception type for TLV fuzz input", e);
            }
        }
    }

    @Test
    void defaultServiceSupportsBothFormatsAndVersionPolicy() {
        DefaultEnvelopeService defaults = new DefaultEnvelopeService();
        assertNotNull(defaults.versionPolicy());
        assertEquals(2, defaults.versionPolicy().currentVersion());
        assertTrue(defaults.supportsVersion(1));
        assertTrue(defaults.supportsVersion(2));
        assertFalse(defaults.supportsVersion(3));
        assertTrue(defaults.versionPolicy().migrationHint(2).contains("current"));
        String legacyHint = defaults.versionPolicy().migrationHint(1);
        assertTrue(legacyHint.contains("unauthenticated"), legacyHint);
        assertTrue(legacyHint.contains("re-encrypt"), legacyHint);
        assertTrue(legacyHint.contains("unified API"), legacyHint);
        assertFalse(defaults.versionPolicy().migrationHint(3).isEmpty());

        for (EnvelopeFormat format : EnvelopeFormat.values()) {
            Envelope decoded = defaults.decode(defaults.encode(aesGcmEnvelope(), format));
            assertSameContents(aesGcmEnvelope(), decoded);
            Envelope bound = defaults.decode(defaults.encode(v2AesGcmEnvelope(), format));
            assertSameContents(v2AesGcmEnvelope(), bound);
            assertEquals(2, bound.version());
        }
    }

    @Test
    void declaredHugeTlvLengthIsRejectedQuickly() {
        byte[] attack = new byte[32];
        byte[] magic = "SPI4ENV1".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, attack, 0, magic.length);
        attack[8] = 0;
        attack[9] = 1;
        attack[10] = 1;
        attack[11] = 0x7F;
        attack[12] = (byte) 0xFF;
        attack[13] = (byte) 0xFF;
        attack[14] = (byte) 0xF0;

        long started = System.nanoTime();
        assertThrows(EnvelopeException.class, () -> service.decode(attack));
        long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
        assertTrue(elapsedMillis < 2_000L, "huge declared length must fail fast");
    }
}