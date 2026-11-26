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
import java.nio.charset.StandardCharsets;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class EnvelopeCodecTest {

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
}