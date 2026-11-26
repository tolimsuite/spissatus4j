package cn.tolim.spissatus4j.envelope;

import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertErrorCode;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertSameContents;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.envelope.codec.JsonEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.codec.TlvEnvelopeCodec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class EnvelopeCodecTest {

    private static final String GOLDEN_V1_JSON =
            "{\"version\":1,\"algorithm\":\"AES-GCM\",\"keyId\":\"key-1\",\"keyVersion\":2,"
                    + "\"nonce\":\"AQIDBAUGBwgJCgsM\",\"salt\":\"AgMEBQYHCAkKCwwNDg8QEQ==\","
                    + "\"aad\":\"YWFkLWNvbnRleHQ=\","
                    + "\"ciphertext\":\"AwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISI=\","
                    + "\"tag\":\"BAUGBwgJCgsMDQ4PEBESEw==\","
                    + "\"createdAt\":\"2026-01-02T03:04:05.123Z\","
                    + "\"kdf\":{\"algorithm\":\"ARGON2ID\",\"parameters\":{\"iterations\":\"2\","
                    + "\"memoryKib\":\"1024\",\"outputBytes\":\"32\",\"parallelism\":\"1\","
                    + "\"version\":\"19\"}},"
                    + "\"attributes\":{\"purpose\":\"unit-test\",\"tenant\":\"acme\"},"
                    + "\"format\":\"JSON\",\"encoding\":\"BASE64\"}";

    private static final String GOLDEN_V1_TLV =
            "53504934454e5631000101000000f30001000000074145532d47434d0002000000056b65792d31"
                    + "000300000008000000000000000200040000000c0102030405060708090a0b0c000500000010"
                    + "02030405060708090a0b0c0d0e0f101100060000000b6161642d636f6e746578740007000000"
                    + "080000019b7ca98d0300080000002e0000000200000007707572706f736500000009756e6974"
                    + "2d746573740000000674656e616e740000000461636d6500090000004c4152474f4e3249443b"
                    + "697465726174696f6e733d323b6d656d6f72794b69623d313032343b6f757470757442797465"
                    + "733d33323b706172616c6c656c69736d3d313b76657273696f6e3d3139000000200304050607"
                    + "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122000000100405060708090a0b"
                    + "0c0d0e0f10111213";

    private final TlvEnvelopeCodec tlv = new TlvEnvelopeCodec();
    private final JsonEnvelopeCodec json = new JsonEnvelopeCodec();

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static String jsonText(Envelope envelope) {
        return new String(new JsonEnvelopeCodec().encode(envelope), StandardCharsets.UTF_8);
    }

    @Test
    void formatIdentifiersAndSniffing() {
        assertEquals("TLV", tlv.formatId());
        assertEquals("JSON", json.formatId());

        byte[] tlvBytes = tlv.encode(TestEnvelopes.aesGcmEnvelope());
        byte[] jsonBytes = json.encode(TestEnvelopes.aesGcmEnvelope());
        assertTrue(tlv.sniff(tlvBytes));
        assertFalse(json.sniff(tlvBytes));
        assertTrue(json.sniff(jsonBytes));
        assertFalse(tlv.sniff(jsonBytes));
        assertTrue(json.sniff(("\n\t  " + new String(jsonBytes, StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8)));

        assertFalse(tlv.sniff(null));
        assertFalse(json.sniff(null));
        assertFalse(tlv.sniff(new byte[0]));
        assertFalse(json.sniff(new byte[0]));
        assertFalse(tlv.sniff(ascii("SPI4")));
        assertFalse(json.sniff(ascii("[]")));
    }

    @Test
    void decodeSetsStructuralFormatAndRawEncoding() {
        Envelope tlvDecoded = tlv.decode(tlv.encode(TestEnvelopes.aesGcmEnvelope()));
        assertEquals(EnvelopeFormat.TLV, tlvDecoded.format());
        assertEquals(BinaryEncoding.RAW, tlvDecoded.binaryEncoding());
        assertSameContents(TestEnvelopes.aesGcmEnvelope(), tlvDecoded);

        Envelope jsonDecoded = json.decode(json.encode(TestEnvelopes.aesGcmEnvelope()));
        assertEquals(EnvelopeFormat.JSON, jsonDecoded.format());
        assertEquals(BinaryEncoding.RAW, jsonDecoded.binaryEncoding());
        assertSameContents(TestEnvelopes.aesGcmEnvelope(), jsonDecoded);
    }

    @Test
    void emptyHkdfInfoRoundTripsThroughTlvAndAcrossFormats() {
        Envelope original = TestEnvelopes.aesGcmEnvelopeBuilder()
                .kdfParameters(new KdfParameters.Hkdf(32, new byte[0], "HmacSHA256"))
                .build();
        byte[] tlvBytes = tlv.encode(original);
        Envelope tlvDecoded = tlv.decode(tlvBytes);
        assertSameContents(original, tlvDecoded);

        byte[] jsonBytes = json.encode(tlvDecoded);
        Envelope jsonDecoded = json.decode(jsonBytes);
        assertSameContents(original, jsonDecoded);
        assertArrayEquals(tlvBytes, tlv.encode(jsonDecoded),
                "TLV -> JSON -> TLV must be byte-identical for empty HKDF info");
    }

    @Test
    void tlvRejectsReservedAndUnknownTags() {
        byte[] encoded = tlv.encode(TestEnvelopes.simpleAesGcmEnvelope());
        byte[] reserved = encoded.clone();
        reserved[15] = 0;
        reserved[16] = 10;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(reserved));

        byte[] unknown = encoded.clone();
        unknown[15] = 0;
        unknown[16] = 42;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(unknown));
    }

    @Test
    void tlvRejectsDuplicateOrUnsortedTags() {
        byte[] encoded = tlv.encode(TestEnvelopes.simpleAesGcmEnvelope());
        byte[] unsorted = encoded.clone();
        unsorted[15] = 0;
        unsorted[16] = 3;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(unsorted));
    }

    @Test
    void tlvRejectsWrongFormatHintAndNegativeLengths() {
        byte[] encoded = tlv.encode(TestEnvelopes.simpleAesGcmEnvelope());
        byte[] wrongHint = encoded.clone();
        wrongHint[10] = 2;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(wrongHint));

        byte[] negativeHeader = encoded.clone();
        negativeHeader[11] = (byte) 0xFF;
        negativeHeader[12] = (byte) 0xFF;
        negativeHeader[13] = (byte) 0xFF;
        negativeHeader[14] = (byte) 0xFF;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(negativeHeader));

        int headerLength = ((encoded[11] & 0xFF) << 24)
                | ((encoded[12] & 0xFF) << 16)
                | ((encoded[13] & 0xFF) << 8)
                | (encoded[14] & 0xFF);
        int ciphertextLengthOffset = 15 + headerLength;
        byte[] negativeCiphertext = encoded.clone();
        negativeCiphertext[ciphertextLengthOffset] = (byte) 0xFF;
        negativeCiphertext[ciphertextLengthOffset + 1] = (byte) 0xFF;
        negativeCiphertext[ciphertextLengthOffset + 2] = (byte) 0xFF;
        negativeCiphertext[ciphertextLengthOffset + 3] = (byte) 0xFF;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(negativeCiphertext));
    }

    @Test
    void jsonRejectsDuplicateFields() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String duplicated = original.replaceFirst("\\{", "{\"version\":1,");
        assertNotEquals(original, duplicated);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(duplicated.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonRejectsUnknownFields() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String mutated = original.replaceFirst("\\{", "{\"evil\":\"x\",");
        assertNotEquals(original, mutated);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(mutated.getBytes(StandardCharsets.UTF_8)));

        String kdfMutation = original.replace("\"parameters\":{",
                "\"parameters\":{\"bogus\":\"1\",");
        assertNotEquals(original, kdfMutation);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(kdfMutation.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonRejectsWrongFieldTypes() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String textVersion = original.replace("\"version\":1", "\"version\":\"1\"");
        assertNotEquals(original, textVersion);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(textVersion.getBytes(StandardCharsets.UTF_8)));

        String fractionalVersion = original.replace("\"keyVersion\":2", "\"keyVersion\":2.5");
        assertNotEquals(original, fractionalVersion);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(fractionalVersion.getBytes(StandardCharsets.UTF_8)));

        String numericAttribute = original.replace("\"purpose\":\"unit-test\"", "\"purpose\":5");
        assertNotEquals(original, numericAttribute);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(numericAttribute.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonRejectsInvalidBase64() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String mutated = original.replaceAll("\"ciphertext\":\"[^\"]*\"", "\"ciphertext\":\"%%%\"");
        assertNotEquals(original, mutated);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(mutated.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonRejectsTrailingContent() {
        byte[] encoded = json.encode(TestEnvelopes.aesGcmEnvelope());
        byte[] trailing = new byte[encoded.length + 2];
        System.arraycopy(encoded, 0, trailing, 0, encoded.length);
        trailing[encoded.length] = ' ';
        trailing[encoded.length + 1] = '1';
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> json.decode(trailing));
    }

    @Test
    void jsonRejectsWrongFormatOrEncodingMarkers() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String wrongFormat = original.replace("\"format\":\"JSON\"", "\"format\":\"TLV\"");
        assertNotEquals(original, wrongFormat);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(wrongFormat.getBytes(StandardCharsets.UTF_8)));

        String wrongEncoding = original.replace("\"encoding\":\"BASE64\"", "\"encoding\":\"HEX\"");
        assertNotEquals(original, wrongEncoding);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(wrongEncoding.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonRejectsMissingFields() {
        String original = jsonText(TestEnvelopes.aesGcmEnvelope());
        String missingEncryption = original.replaceAll("\"ciphertext\":\"[^\"]*\",", "");
        assertNotEquals(original, missingEncryption);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(missingEncryption.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void jsonPrefixFuzzInputsFailClosed() {
        SplittableRandom random = new SplittableRandom(0xBAD5EEDL);
        for (int iteration = 0; iteration < 500; iteration++) {
            int length = 1 + random.nextInt(512);
            byte[] input = new byte[length];
            input[0] = '{';
            for (int index = 1; index < length; index++) {
                input[index] = (byte) random.nextInt(256);
            }
            try {
                json.decode(input);
            } catch (EnvelopeException expected) {
                // fail-closed
            } catch (RuntimeException e) {
                fail("Unexpected exception type for JSON fuzz input", e);
            }
        }
    }

    @Test
    void codecMaximumSizeIsEnforced() {
        byte[] encoded = tlv.encode(TestEnvelopes.aesGcmEnvelope());
        TlvEnvelopeCodec bounded = new TlvEnvelopeCodec(encoded.length);
        assertThrows(EnvelopeException.class, () -> bounded.decode(
                java.util.Arrays.copyOf(encoded, encoded.length + 1)));

        JsonEnvelopeCodec boundedJson = new JsonEnvelopeCodec(16);
        String jsonText = jsonText(TestEnvelopes.aesGcmEnvelope());
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> boundedJson.decode(jsonText.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void versionOneEncodingsRemainByteForByteCompatible() {
        Envelope envelope = TestEnvelopes.aesGcmEnvelope();
        assertEquals(GOLDEN_V1_JSON, jsonText(envelope));
        assertEquals(GOLDEN_V1_TLV, HexFormat.of().formatHex(tlv.encode(envelope)));
        assertFalse(GOLDEN_V1_JSON.contains("headerHash"));
        assertSameContents(envelope, json.decode(GOLDEN_V1_JSON.getBytes(StandardCharsets.UTF_8)));
        assertSameContents(envelope,
                tlv.decode(HexFormat.of().parseHex(GOLDEN_V1_TLV)));
    }

    @Test
    void versionTwoRoundTripsThroughBothCodecs() {
        Envelope original = TestEnvelopes.v2AesGcmEnvelope();
        byte[] tlvBytes = tlv.encode(original);
        Envelope tlvDecoded = tlv.decode(tlvBytes);
        assertEquals(2, tlvDecoded.version());
        assertArrayEquals(original.headerHash(), tlvDecoded.headerHash());
        assertSameContents(original, tlvDecoded);

        byte[] jsonBytes = json.encode(tlvDecoded);
        assertTrue(new String(jsonBytes, StandardCharsets.UTF_8).contains("\"headerHash\":"));
        Envelope jsonDecoded = json.decode(jsonBytes);
        assertEquals(2, jsonDecoded.version());
        assertArrayEquals(original.headerHash(), jsonDecoded.headerHash());
        assertSameContents(original, jsonDecoded);
        assertArrayEquals(tlvBytes, tlv.encode(jsonDecoded),
                "TLV -> JSON -> TLV must be byte-identical for version 2");
    }

    @Test
    void versionTwoRequiresHeaderHash() {
        Envelope versionTwo = TestEnvelopes.v2AesGcmEnvelope();
        String text = jsonText(versionTwo);
        String missing = text.replaceAll("\"headerHash\":\"[^\"]*\",", "");
        assertNotEquals(text, missing);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(missing.getBytes(StandardCharsets.UTF_8)));

        byte[] tlvWithoutHash = tlv.encode(TestEnvelopes.simpleAesGcmEnvelope()).clone();
        tlvWithoutHash[8] = 0;
        tlvWithoutHash[9] = 2;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(tlvWithoutHash));
    }

    @Test
    void versionOneRejectsHeaderHash() {
        Envelope versionTwo = TestEnvelopes.v2AesGcmEnvelope();
        String text = jsonText(versionTwo);
        String downgraded = text.replace("\"version\":2", "\"version\":1");
        assertNotEquals(text, downgraded);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(downgraded.getBytes(StandardCharsets.UTF_8)));

        String emptyHash = jsonText(TestEnvelopes.aesGcmEnvelope())
                .replaceFirst("\\{", "{\"headerHash\":\"\",");
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(emptyHash.getBytes(StandardCharsets.UTF_8)));

        byte[] tlvWithHash = tlv.encode(versionTwo).clone();
        tlvWithHash[8] = 0;
        tlvWithHash[9] = 1;
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> tlv.decode(tlvWithHash));
    }

    @Test
    void versionTwoJsonStillRejectsUnknownDuplicateAndWronglyTypedFields() {
        String original = jsonText(TestEnvelopes.v2AesGcmEnvelope());

        String unknown = original.replaceFirst("\\{", "{\"evil\":\"x\",");
        assertNotEquals(original, unknown);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(unknown.getBytes(StandardCharsets.UTF_8)));

        String duplicate = original.replaceFirst("\\{", "{\"headerHash\":\"AAAA\",");
        assertNotEquals(original, duplicate);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(duplicate.getBytes(StandardCharsets.UTF_8)));

        String numericHash = original.replaceAll("\"headerHash\":\"[^\"]*\"",
                "\"headerHash\":5");
        assertNotEquals(original, numericHash);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(numericHash.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void versionTwoRejectsWrongHeaderHashLengthInTlv() {
        byte[] encoded = tlv.encode(TestEnvelopes.v2AesGcmEnvelope());
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> tlv.decode(withHeaderHashLength(encoded, 31)));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> tlv.decode(withHeaderHashLength(encoded, 33)));
    }

    /**
     * Rewrites the final header entry (tag 11) of a version 2 envelope to the
     * requested value length, adjusting the header length accordingly.
     */
    private static byte[] withHeaderHashLength(byte[] encoded, int newLength) {
        int headerLength = readInt(encoded, 11);
        int headerEnd = 15 + headerLength;
        int tagLengthOffset = headerEnd - 32 - 4;
        ByteArrayOutputStream output = new ByteArrayOutputStream(encoded.length + newLength - 32);
        output.write(encoded, 0, tagLengthOffset);
        writeInt(output, newLength);
        byte[] value = Arrays.copyOfRange(encoded, tagLengthOffset + 4, tagLengthOffset + 4 + 32);
        output.write(Arrays.copyOf(value, newLength), 0, newLength);
        output.write(encoded, headerEnd, encoded.length - headerEnd);
        byte[] result = output.toByteArray();
        int updatedHeaderLength = headerLength - 32 + newLength;
        result[11] = (byte) (updatedHeaderLength >>> 24);
        result[12] = (byte) (updatedHeaderLength >>> 16);
        result[13] = (byte) (updatedHeaderLength >>> 8);
        result[14] = (byte) updatedHeaderLength;
        return result;
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream output, int value) {
        output.write((value >>> 24) & 0xFF);
        output.write((value >>> 16) & 0xFF);
        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }
}