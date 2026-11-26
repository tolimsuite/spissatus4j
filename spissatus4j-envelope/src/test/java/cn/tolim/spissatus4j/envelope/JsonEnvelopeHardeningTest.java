package cn.tolim.spissatus4j.envelope;

import static cn.tolim.spissatus4j.envelope.TestEnvelopes.aesGcmEnvelope;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.aesGcmEnvelopeBuilder;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertErrorCode;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertSameContents;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.envelope.codec.JsonEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.codec.TlvEnvelopeCodec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for strict JSON input handling: UTF-8 only, well-formed
 * strings and structural limits enforced before the Jackson tree is built.
 */
class JsonEnvelopeHardeningTest {

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");
    private static final Charset UTF_32LE = Charset.forName("UTF-32LE");

    private final JsonEnvelopeCodec json = new JsonEnvelopeCodec();

    private static byte[] concat(byte[] prefix, byte[] body) {
        byte[] result = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(body, 0, result, prefix.length, body.length);
        return result;
    }

    private static String jsonText(Envelope envelope) {
        return new String(new JsonEnvelopeCodec().encode(envelope), StandardCharsets.UTF_8);
    }

    private static void writeAscii(ByteArrayOutputStream output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        output.write(bytes, 0, bytes.length);
    }

    private static byte[] attributeDocument(int attributes) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(attributes * 16 + 64);
        writeAscii(output, "{\"attributes\":{");
        for (int index = 0; index < attributes; index++) {
            if (index > 0) {
                output.write(',');
            }
            writeAscii(output, "\"k" + index + "\":\"v\"");
        }
        writeAscii(output, "}}");
        return output.toByteArray();
    }

    private static byte[] kdfDocument(int parameters) {
        String base = jsonText(aesGcmEnvelope());
        String marker = "\"parameters\":{";
        int start = base.indexOf(marker) + marker.length();
        ByteArrayOutputStream output = new ByteArrayOutputStream(base.length() + parameters * 16 + 64);
        writeAscii(output, base.substring(0, start));
        for (int index = 0; index < parameters; index++) {
            if (index > 0) {
                output.write(',');
            }
            writeAscii(output, "\"x" + index + "\":\"1\"");
        }
        writeAscii(output, base.substring(start));
        return output.toByteArray();
    }

    @Test
    void utf8BomIsAccepted() {
        byte[] encoded = json.encode(aesGcmEnvelope());
        byte[] withBom = concat(UTF8_BOM, encoded);
        assertTrue(json.sniff(withBom), "a UTF-8 BOM must not defeat format sniffing");
        assertSameContents(aesGcmEnvelope(), json.decode(withBom));
    }

    @Test
    void utf16AndUtf32DocumentsAreRejected() {
        String text = jsonText(aesGcmEnvelope());
        List<byte[]> documents = List.of(
                concat(new byte[]{(byte) 0xFE, (byte) 0xFF},
                        text.getBytes(StandardCharsets.UTF_16BE)),
                concat(new byte[]{(byte) 0xFF, (byte) 0xFE},
                        text.getBytes(StandardCharsets.UTF_16LE)),
                concat(new byte[]{0, 0, (byte) 0xFE, (byte) 0xFF},
                        text.getBytes(UTF_32BE)),
                concat(new byte[]{(byte) 0xFF, (byte) 0xFE, 0, 0},
                        text.getBytes(UTF_32LE)),
                text.getBytes(StandardCharsets.UTF_16BE),
                text.getBytes(StandardCharsets.UTF_16LE));
        for (byte[] document : documents) {
            assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> json.decode(document));
        }
    }

    @Test
    void unpairedSurrogatesInAttributeKeysAndValuesAreRejected() {
        String original = jsonText(aesGcmEnvelope());
        String valueMutation = original.replace("\"purpose\":\"unit-test\"", "\"purpose\":\"\\uD800\"");
        assertNotEquals(original, valueMutation);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(valueMutation.getBytes(StandardCharsets.UTF_8)));

        String keyMutation = original.replace("\"purpose\":", "\"\\uD800\":");
        assertNotEquals(original, keyMutation);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED,
                () -> json.decode(keyMutation.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void wellFormedNonAsciiAttributesRoundTrip() {
        Envelope original = aesGcmEnvelopeBuilder()
                .attributes(Map.of("grüße", "值 😀"))
                .build();
        Envelope decoded = json.decode(json.encode(original));
        assertEquals(original.attributes(), decoded.attributes());
        assertSameContents(original, decoded);
    }

    @Test
    void attributeAndKdfParameterCountsAtTheLimitPlusOneAreRejected() {
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> json.decode(attributeDocument(65)));
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> json.decode(kdfDocument(17)));
    }

    @Test
    void maximumLengthAttributeKeyAndValueAreAccepted() {
        String key = "k".repeat(128);
        String value = "v".repeat(4096);
        Envelope original = aesGcmEnvelopeBuilder().attributes(Map.of(key, value)).build();
        Envelope decoded = json.decode(json.encode(original));
        assertEquals(original.attributes(), decoded.attributes());
    }

    @Test
    void maximumAttributeCountIsAccepted() {
        Map<String, String> attributes = new HashMap<>();
        for (int index = 0; index < 64; index++) {
            attributes.put("k" + index, "v" + index);
        }
        Envelope full = aesGcmEnvelopeBuilder().attributes(attributes).build();
        assertEquals(64, json.decode(json.encode(full)).attributes().size());
    }

    @Test
    void oversizedAttributeSetsAreRejectedBeforeMaterializingTheDocument() {
        byte[] document = attributeDocument(5_000_000);
        JsonEnvelopeCodec codec = new JsonEnvelopeCodec(document.length + 1024);
        long started = System.nanoTime();
        EnvelopeException failure = assertThrows(EnvelopeException.class, () -> codec.decode(document));
        long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
        assertEquals(ErrorCode.ENVELOPE_MALFORMED, failure.errorCode());
        assertTrue(failure.getMessage().contains("Too many envelope attributes"),
                "structural limit must reject the attribute count: " + failure.getMessage());
        assertTrue(elapsedMillis < 1_500L,
                "oversized attribute sets must be rejected before the document is materialized (took "
                        + elapsedMillis + " ms)");
    }

    @Test
    void unpairedSurrogatesAreRejectedOnEncoding() {
        Envelope envelope = aesGcmEnvelopeBuilder()
                .format(cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat.JSON)
                .attributes(Map.of("bad", "\uD800"))
                .build();
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED, () -> json.encode(envelope));
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> new TlvEnvelopeCodec().encode(envelope));
    }

    @Test
    void oversizedKdfParameterSetsAreRejectedBeforeMaterializingTheDocument() {
        byte[] document = kdfDocument(5_000_000);
        JsonEnvelopeCodec codec = new JsonEnvelopeCodec(document.length + 1024);
        long started = System.nanoTime();
        EnvelopeException failure = assertThrows(EnvelopeException.class, () -> codec.decode(document));
        long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
        assertEquals(ErrorCode.ENVELOPE_MALFORMED, failure.errorCode());
        assertTrue(failure.getMessage().contains("Too many KDF parameters"),
                "structural limit must reject the KDF parameter count: " + failure.getMessage());
        assertTrue(elapsedMillis < 1_500L,
                "oversized KDF parameter sets must be rejected before the document is materialized (took "
                        + elapsedMillis + " ms)");
    }
}