package cn.tolim.spissatus4j.envelope.codec;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.envelope.internal.EnvelopeLimits;
import cn.tolim.spissatus4j.envelope.internal.KdfCodec;
import cn.tolim.spissatus4j.envelope.internal.Utf8;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Strict JSON envelope codec. Jackson is confined to this class; no Jackson
 * types appear in the public API.
 *
 * <p>The JSON object contains exactly: {@code version}, {@code algorithm},
 * {@code keyId}, {@code keyVersion}, {@code nonce}, {@code salt}, {@code aad},
 * {@code ciphertext}, {@code tag}, {@code createdAt}, {@code kdf},
 * {@code attributes}, {@code format} and {@code encoding}. Binary values are
 * base64; timestamps are ISO-8601 instants. Unknown, duplicate or wrongly
 * typed fields are rejected.</p>
 */
public final class JsonEnvelopeCodec implements EnvelopeCodec {

    public static final String FORMAT_ID = "JSON";

    private static final String FORMAT_MARKER = "JSON";
    private static final String ENCODING_MARKER = "BASE64";

    private static final Set<String> FIELDS = Set.of(
            "version", "algorithm", "keyId", "keyVersion", "nonce", "salt", "aad",
            "ciphertext", "tag", "createdAt", "kdf", "attributes", "format", "encoding");

    private static final Set<String> KDF_FIELDS = Set.of("algorithm", "parameters");

    private static final int SNIFF_WHITESPACE_LIMIT = 64;

    /**
     * Hard token ceiling: a valid envelope needs fewer than 200 tokens, so
     * rejecting beyond this bounds any Jackson tree materialization.
     */
    private static final int MAX_JSON_TOKENS = 1024;

    private static final int UTF8_BOM_LENGTH = 3;

    private final int maxBytes;
    private final ObjectMapper mapper;

    public JsonEnvelopeCodec() {
        this(EnvelopeLimits.DEFAULT_MAX_BYTES);
    }

    public JsonEnvelopeCodec(int maxBytes) {
        if (maxBytes < 1) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Maximum envelope size must be positive");
        }
        this.maxBytes = maxBytes;
        JsonFactory factory = JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(32)
                        .maxNumberLength(100)
                        .maxStringLength(maxBytes)
                        .maxNameLength(EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES)
                        .maxDocumentLength(maxBytes)
                        .maxTokenCount(MAX_JSON_TOKENS)
                        .build())
                .build();
        this.mapper = new ObjectMapper(factory);
        this.mapper.enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    @Override
    public String formatId() {
        return FORMAT_ID;
    }

    @Override
    public byte[] encode(Envelope envelope) {
        if (envelope == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Envelope is required");
        }
        try {
            ObjectNode root = mapper.createObjectNode();
            root.put("version", envelope.version());
            root.put("algorithm", envelope.algorithm().id());
            root.put("keyId", envelope.keyId().value());
            root.put("keyVersion", envelope.keyVersion().value());
            root.put("nonce", encodeBase64(envelope.nonce().asBytes()));
            root.put("salt", encodeBase64(envelope.salt().asBytes()));
            root.put("aad", encodeBase64(envelope.aad().asBytes()));
            root.put("ciphertext", encodeBase64(envelope.ciphertext()));
            root.put("tag", encodeBase64(envelope.tag()));
            root.put("createdAt", envelope.createdAt().toString());
            writeKdf(root, envelope.kdfParameters());
            writeAttributes(root, envelope.attributes());
            root.put("format", FORMAT_MARKER);
            root.put("encoding", ENCODING_MARKER);
            byte[] encoded = mapper.writeValueAsBytes(root);
            if (encoded.length > maxBytes) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope exceeds the maximum encoded size");
            }
            return encoded;
        } catch (EnvelopeException e) {
            throw e;
        } catch (JsonProcessingException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Envelope encoding failed");
        } catch (RuntimeException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Envelope encoding failed");
        }
    }

    @Override
    public Envelope decode(byte[] encoded) {
        if (encoded == null) {
            throw malformed("Envelope bytes are required");
        }
        if (encoded.length > maxBytes) {
            throw malformed("Envelope exceeds the maximum size");
        }
        requireUtf8Input(encoded);
        scanStructure(encoded);
        try (JsonParser parser = mapper.getFactory().createParser(encoded)) {
            JsonNode root = mapper.readTree(parser);
            if (root == null || !root.isObject()) {
                throw malformed("Envelope JSON must be an object");
            }
            if (parser.nextToken() != null) {
                throw malformed("Trailing content after envelope JSON");
            }
            return parseRoot(root);
        } catch (EnvelopeException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw malformed("Envelope JSON is malformed");
        }
    }

    @Override
    public boolean sniff(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return false;
        }
        int start = startsWithUtf8Bom(encoded) ? UTF8_BOM_LENGTH : 0;
        int limit = Math.min(encoded.length, start + SNIFF_WHITESPACE_LIMIT);
        for (int index = start; index < limit; index++) {
            byte value = encoded[index];
            if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
                continue;
            }
            return value == '{';
        }
        return false;
    }

    /**
     * Rejects UTF-16/UTF-32 BOMs, NUL-interleaved text and malformed UTF-8
     * before Jackson can guess an encoding. A UTF-8 BOM is permitted.
     */
    private static void requireUtf8Input(byte[] encoded) {
        if (startsWith(encoded, 0x00, 0x00, 0xFE, 0xFF)
                || startsWith(encoded, 0xFF, 0xFE, 0x00, 0x00)
                || startsWith(encoded, 0xFE, 0xFF)
                || startsWith(encoded, 0xFF, 0xFE)) {
            throw malformed("Envelope JSON must be UTF-8 encoded text");
        }
        for (byte value : encoded) {
            if (value == 0) {
                throw malformed("Envelope JSON must be UTF-8 encoded text");
            }
        }
        try {
            Utf8.validate(encoded);
        } catch (IllegalArgumentException e) {
            throw malformed("Envelope JSON must be UTF-8 encoded text");
        }
    }

    private static boolean startsWithUtf8Bom(byte[] encoded) {
        return startsWith(encoded, 0xEF, 0xBB, 0xBF);
    }

    private static boolean startsWith(byte[] encoded, int... prefix) {
        if (encoded.length < prefix.length) {
            return false;
        }
        for (int index = 0; index < prefix.length; index++) {
            if ((encoded[index] & 0xFF) != prefix[index]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Streaming structural pass: counts object fields per envelope section and
     * rejects over-limit documents before {@code readTree} can materialize
     * them. Jackson constraints cap tokens, names, strings and nesting; this
     * pass adds the section-specific attribute and KDF parameter limits.
     */
    private void scanStructure(byte[] encoded) {
        try (JsonParser parser = mapper.getFactory().createParser(encoded)) {
            Deque<ScanContext> contexts = new ArrayDeque<>();
            boolean rootStarted = false;
            String pendingField = null;
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                if (!rootStarted && token != JsonToken.START_OBJECT) {
                    throw malformed("Envelope JSON must be an object");
                }
                if (rootStarted && contexts.isEmpty()) {
                    throw malformed("Trailing content after envelope JSON");
                }
                switch (token) {
                    case START_OBJECT -> {
                        ScanContext child;
                        if (!rootStarted) {
                            child = new ScanContext(ScanKind.ROOT);
                        } else {
                            ScanContext parent = contexts.peek();
                            child = parent == null ? null : parent.child(pendingField);
                        }
                        if (child == null) {
                            throw malformed("Unexpected nested JSON object");
                        }
                        contexts.push(child);
                        rootStarted = true;
                        pendingField = null;
                    }
                    case END_OBJECT -> {
                        if (contexts.isEmpty()) {
                            throw malformed("Unexpected JSON structure");
                        }
                        contexts.pop();
                        pendingField = null;
                    }
                    case FIELD_NAME -> {
                        ScanContext context = contexts.peek();
                        if (context == null) {
                            throw malformed("Unexpected JSON structure");
                        }
                        String name = parser.currentName();
                        if (name == null || !Utf8.isWellFormed(name)) {
                            throw malformed("Envelope JSON contains an unpaired surrogate");
                        }
                        context.recordField();
                        pendingField = name;
                    }
                    case START_ARRAY, END_ARRAY -> throw malformed(
                            "Envelope JSON must not contain arrays");
                    default -> pendingField = null;
                }
            }
            if (!rootStarted) {
                throw malformed("Envelope JSON must be an object");
            }
        } catch (EnvelopeException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw malformed("Envelope JSON is malformed");
        }
    }

    private Envelope parseRoot(JsonNode root) {
        Iterator<String> names = root.fieldNames();
        while (names.hasNext()) {
            if (!FIELDS.contains(names.next())) {
                throw malformed("Unknown envelope field");
            }
        }
        for (String field : FIELDS) {
            if (!root.has(field)) {
                throw malformed("Missing envelope field");
            }
        }
        int version = requireInt(root, "version");
        if (version < 1) {
            throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                    "Unsupported envelope version");
        }
        long keyVersion = requireLong(root, "keyVersion");
        if (keyVersion < 1) {
            throw malformed("Invalid key version");
        }
        String format = requireText(root, "format");
        if (!FORMAT_MARKER.equals(format)) {
            throw malformed("Unexpected envelope format marker");
        }
        String encoding = requireText(root, "encoding");
        if (!ENCODING_MARKER.equals(encoding)) {
            throw malformed("Unexpected envelope encoding marker");
        }
        Envelope.Builder builder = Envelope.builder()
                .version(version)
                .algorithm(parseAlgorithm(requireText(root, "algorithm")))
                .keyId(parseKeyId(requireText(root, "keyId")))
                .keyVersion(KeyVersion.of(keyVersion))
                .nonce(Nonce.of(decodeBase64(root, "nonce")))
                .salt(Salt.of(decodeBase64(root, "salt")))
                .kdfParameters(parseKdf(root.get("kdf")))
                .aad(AAD.of(decodeBase64(root, "aad")))
                .ciphertext(decodeBase64(root, "ciphertext"))
                .tag(decodeBase64(root, "tag"))
                .createdAt(parseInstant(requireText(root, "createdAt")))
                .format(EnvelopeFormat.JSON)
                .binaryEncoding(BinaryEncoding.RAW)
                .attributes(parseAttributes(root.get("attributes")));
        return builder.build();
    }

    private static void writeKdf(ObjectNode root, KdfParameters parameters) {
        if (parameters == null) {
            root.putNull("kdf");
            return;
        }
        ObjectNode node = root.putObject("kdf");
        node.put("algorithm", parameters.algorithm().id());
        ObjectNode parametersNode = node.putObject("parameters");
        TreeMap<String, String> sorted = new TreeMap<>(parameters.toMap());
        sorted.remove("algorithm");
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            parametersNode.put(entry.getKey(), entry.getValue());
        }
    }

    private static void writeAttributes(ObjectNode root, Map<String, String> attributes) {
        if (attributes.size() > EnvelopeLimits.MAX_ATTRIBUTES) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Too many envelope attributes");
        }
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (!Utf8.isWellFormed(entry.getKey()) || !Utf8.isWellFormed(entry.getValue())) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must be well-formed Unicode");
            }
        }
        ObjectNode node = root.putObject("attributes");
        TreeMap<String, String> sorted = new TreeMap<>();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || value == null) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must not contain null");
            }
            int keyBytes = Utf8.length(key);
            if (keyBytes < 1 || keyBytes > EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES
                    || Utf8.length(value) > EnvelopeLimits.MAX_ATTRIBUTE_VALUE_BYTES) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attribute length is invalid");
            }
            sorted.put(key, value);
        }
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            node.put(entry.getKey(), entry.getValue());
        }
    }

    private static KdfParameters parseKdf(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isObject()) {
            throw malformed("KDF metadata must be an object");
        }
        Iterator<String> names = node.fieldNames();
        while (names.hasNext()) {
            if (!KDF_FIELDS.contains(names.next())) {
                throw malformed("Unknown KDF field");
            }
        }
        if (!node.has("algorithm") || !node.has("parameters")) {
            throw malformed("Incomplete KDF metadata");
        }
        String algorithm = requireText(node, "algorithm");
        JsonNode parametersNode = node.get("parameters");
        if (!parametersNode.isObject()) {
            throw malformed("KDF parameters must be an object");
        }
        if (parametersNode.size() > EnvelopeLimits.MAX_KDF_PARAMETERS) {
            throw malformed("Too many KDF parameters");
        }
        Map<String, String> parameters = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : parametersNode.properties()) {
            String key = requireWellFormed(entry.getKey());
            if ("algorithm".equals(key) || !entry.getValue().isTextual()) {
                throw malformed("Invalid KDF parameter");
            }
            parameters.put(key, requireWellFormed(entry.getValue().textValue()));
        }
        parameters.put("algorithm", algorithm);
        try {
            return KdfCodec.fromMap(parameters);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid KDF metadata");
        }
    }

    private static Map<String, String> parseAttributes(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw malformed("Envelope attributes must be an object");
        }
        if (node.size() > EnvelopeLimits.MAX_ATTRIBUTES) {
            throw malformed("Too many envelope attributes");
        }
        Map<String, String> attributes = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            String key = requireWellFormed(entry.getKey());
            JsonNode valueNode = entry.getValue();
            if (!valueNode.isTextual()) {
                throw malformed("Envelope attribute values must be strings");
            }
            String value = requireWellFormed(valueNode.textValue());
            int keyBytes = Utf8.length(key);
            if (keyBytes < 1 || keyBytes > EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES
                    || Utf8.length(value) > EnvelopeLimits.MAX_ATTRIBUTE_VALUE_BYTES) {
                throw malformed("Envelope attribute length is invalid");
            }
            attributes.put(key, value);
        }
        return attributes;
    }

    private static String requireWellFormed(String value) {
        if (value == null || !Utf8.isWellFormed(value)) {
            throw malformed("Envelope JSON contains an unpaired surrogate");
        }
        return value;
    }

    private static AlgorithmId parseAlgorithm(String text) {
        if (text.isEmpty()) {
            throw malformed("Missing algorithm identifier");
        }
        try {
            return AlgorithmId.of(text);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid algorithm identifier");
        }
    }

    private static KeyId parseKeyId(String text) {
        if (text.isEmpty()) {
            throw malformed("Missing key identifier");
        }
        try {
            return KeyId.of(text);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid key identifier");
        }
    }

    private static Instant parseInstant(String text) {
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw malformed("Invalid creation time");
        }
    }

    private static int requireInt(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isIntegralNumber() || !node.canConvertToInt()) {
            throw malformed("Invalid numeric envelope field");
        }
        return node.intValue();
    }

    private static long requireLong(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isIntegralNumber() || !node.canConvertToLong()) {
            throw malformed("Invalid numeric envelope field");
        }
        return node.longValue();
    }

    private static String requireText(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isTextual()) {
            throw malformed("Invalid textual envelope field");
        }
        return requireWellFormed(node.textValue());
    }

    private static byte[] decodeBase64(JsonNode root, String field) {
        String text = requireText(root, field);
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid base64 envelope field");
        }
    }

    private static String encodeBase64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static EnvelopeException malformed(String message) {
        return new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, message);
    }

    private enum ScanKind {
        ROOT, KDF, PARAMETERS, ATTRIBUTES
    }

    /** Per-object structural allowance used by the streaming pre-scan. */
    private static final class ScanContext {

        private final ScanKind kind;
        private int fieldCount;

        private ScanContext(ScanKind kind) {
            this.kind = kind;
        }

        private ScanContext child(String fieldName) {
            if (fieldName == null) {
                return null;
            }
            if (kind == ScanKind.ROOT) {
                return switch (fieldName) {
                    case "kdf" -> new ScanContext(ScanKind.KDF);
                    case "attributes" -> new ScanContext(ScanKind.ATTRIBUTES);
                    default -> null;
                };
            }
            if (kind == ScanKind.KDF && "parameters".equals(fieldName)) {
                return new ScanContext(ScanKind.PARAMETERS);
            }
            return null;
        }

        private void recordField() {
            fieldCount++;
            int limit = switch (kind) {
                case ROOT -> FIELDS.size();
                case KDF -> KDF_FIELDS.size();
                case PARAMETERS -> EnvelopeLimits.MAX_KDF_PARAMETERS;
                case ATTRIBUTES -> EnvelopeLimits.MAX_ATTRIBUTES;
            };
            if (fieldCount > limit) {
                throw malformed(switch (kind) {
                    case ROOT -> "Too many envelope fields";
                    case KDF -> "Too many KDF fields";
                    case PARAMETERS -> "Too many KDF parameters";
                    case ATTRIBUTES -> "Too many envelope attributes";
                });
            }
        }
    }
}