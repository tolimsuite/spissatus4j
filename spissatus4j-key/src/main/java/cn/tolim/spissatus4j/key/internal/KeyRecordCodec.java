package cn.tolim.spissatus4j.key.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.RotationPolicy;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * JSON codec for stored key records and non-secret descriptor metadata.
 *
 * <p>All failures are reported as {@link ErrorCode#KEY_PROVIDER_FAILURE} with
 * a generic message so that malformed or tampered records cannot be used as
 * an oracle. Material is encoded as Base64 inside an encrypted payload when
 * used by the file provider.</p>
 */
public final class KeyRecordCodec {

    /**
     * Maximum size of a single stored material blob. Key material is normally a
     * few kilobytes at most; this guard prevents an oversized import from
     * creating a record that the providers cannot read back.
     */
    public static final int MAX_MATERIAL_BYTES = 8 * 1024 * 1024;

    private KeyRecordCodec() {
    }

    public static byte[] encodeStoredKey(StoredKey storedKey) {
        Objects.requireNonNull(storedKey, "storedKey");
        byte[] material = storedKey.material();
        try {
            return encodeStoredKey(storedKey.descriptor(), material, storedKey.materialFormat(),
                    storedKey.encrypted(), storedKey.attributes());
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    /**
     * Encodes a record without taking ownership of the supplied material; the
     * caller remains responsible for wiping the array.
     */
    public static byte[] encodeStoredKey(KeyDescriptor descriptor, byte[] material,
                                         String materialFormat, boolean encrypted,
                                         Map<String, String> providerAttributes) {
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(material, "material");
        if (material.length > MAX_MATERIAL_BYTES) {
            throw new KeyException(ErrorCode.INVALID_PARAMETER,
                    "Key material exceeds the maximum supported size");
        }
        ObjectNode node = descriptorNode(descriptor);
        node.put("materialFormat", materialFormat);
        node.put("encrypted", encrypted);
        node.put("material", Base64.getEncoder().encodeToString(material));
        node.set("providerAttributes", stringObject(providerAttributes));
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (IOException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key record could not be encoded");
        }
    }

    public static StoredKey decodeStoredKey(byte[] payload) {
        Objects.requireNonNull(payload, "payload");
        try {
            JsonNode node = MAPPER.readTree(payload);
            KeyDescriptor descriptor = descriptorFromNode(node);
            String format = requiredText(node, "materialFormat");
            if (!KeyMaterialCodec.isKnownMaterialFormat(format)) {
                throw failure();
            }
            byte[] material = decodeMaterial(node, descriptor);
            boolean encrypted = node.path("encrypted").asBoolean(false);
            Map<String, String> providerAttributes = readStringMap(node.path("providerAttributes"));
            return new StoredKey(descriptor, material, format, encrypted, providerAttributes);
        } catch (KeyException e) {
            throw failure();
        } catch (IOException | RuntimeException e) {
            throw failure();
        }
    }

    public static String encodeMetadata(KeyDescriptor descriptor, String materialFormat) {
        Objects.requireNonNull(descriptor, "descriptor");
        if (!KeyMaterialCodec.isKnownMaterialFormat(materialFormat)) {
            throw failure();
        }
        ObjectNode node = descriptorNode(descriptor);
        node.put("materialFormat", materialFormat);
        return node.toString();
    }

    public static Metadata decodeMetadata(String payload) {
        if (payload == null || payload.isBlank()) {
            throw failure();
        }
        try {
            JsonNode node = MAPPER.readTree(payload);
            KeyDescriptor descriptor = descriptorFromNode(node);
            String format = requiredText(node, "materialFormat");
            if (!KeyMaterialCodec.isKnownMaterialFormat(format)) {
                throw failure();
            }
            return new Metadata(descriptor, format);
        } catch (KeyException e) {
            throw failure();
        } catch (IOException | RuntimeException e) {
            throw failure();
        }
    }

    /**
     * Tombstones persist an empty material string because the material has
     * been destroyed. Empty or missing material is accepted only for terminal
     * states; every other record must carry material so that corruption is not
     * silently interpreted as a destroyed key.
     */
    private static byte[] decodeMaterial(JsonNode node, KeyDescriptor descriptor) {
        JsonNode value = node.get("material");
        if (value == null || value.isNull()) {
            if (!descriptor.state().terminal()) {
                throw failure();
            }
            return new byte[0];
        }
        if (!value.isTextual()) {
            throw failure();
        }
        String encoded = value.asText();
        if (encoded.isEmpty()) {
            if (!descriptor.state().terminal()) {
                throw failure();
            }
            return new byte[0];
        }
        byte[] material;
        try {
            material = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw failure();
        }
        if (material.length > MAX_MATERIAL_BYTES) {
            throw failure();
        }
        return material;
    }

    private static ObjectNode descriptorNode(KeyDescriptor descriptor) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("keyId", descriptor.keyId().value());
        node.put("version", descriptor.version().value());
        node.put("type", descriptor.type().name());
        node.put("algorithm", descriptor.algorithm().id());
        node.put("keyBits", descriptor.keyBits());
        node.put("state", descriptor.state().name());
        ArrayNode usages = node.putArray("usages");
        descriptor.usages().stream().map(Enum::name).sorted().forEach(usages::add);
        node.put("tenantId", descriptor.tenantId());
        node.put("createdAt", descriptor.createdAt().toString());
        if (descriptor.activatedAt() == null) {
            node.putNull("activatedAt");
        } else {
            node.put("activatedAt", descriptor.activatedAt().toString());
        }
        if (descriptor.expiresAt() == null) {
            node.putNull("expiresAt");
        } else {
            node.put("expiresAt", descriptor.expiresAt().toString());
        }
        RotationPolicy rotation = descriptor.rotationPolicy();
        if (rotation == null) {
            node.putNull("rotation");
        } else {
            ObjectNode rotationNode = node.putObject("rotation");
            if (rotation.maxAge() == null) {
                rotationNode.putNull("maxAgeMillis");
            } else {
                long millis = rotation.maxAge().toMillis();
                rotationNode.put("maxAgeMillis", Math.max(1L, millis));
            }
            rotationNode.put("maxOperations", rotation.maxOperations());
            rotationNode.put("retainVersions", rotation.retainVersions());
        }
        node.put("exportable", descriptor.exportable());
        node.put("usageCount", descriptor.usageCount());
        node.set("attributes", stringObject(descriptor.attributes()));
        if (descriptor.fingerprint() == null) {
            node.putNull("fingerprint");
        } else {
            node.put("fingerprint", descriptor.fingerprint());
        }
        return node;
    }

    private static KeyDescriptor descriptorFromNode(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw failure();
        }
        Set<KeyUsage> usages = new LinkedHashSet<>();
        JsonNode usagesNode = node.get("usages");
        if (usagesNode == null || !usagesNode.isArray()) {
            throw failure();
        }
        for (JsonNode usage : usagesNode) {
            usages.add(KeyUsage.valueOf(usage.asText()));
        }
        RotationPolicy rotation = null;
        JsonNode rotationNode = node.get("rotation");
        if (rotationNode != null && rotationNode.isObject()) {
            Duration maxAge = null;
            JsonNode maxAgeNode = rotationNode.get("maxAgeMillis");
            if (maxAgeNode != null && !maxAgeNode.isNull()) {
                maxAge = Duration.ofMillis(maxAgeNode.asLong());
            }
            rotation = new RotationPolicy(maxAge, rotationNode.path("maxOperations").asLong(),
                    rotationNode.path("retainVersions").asInt());
        }
        String fingerprint = nullableText(node, "fingerprint");
        return KeyDescriptor.builder()
                .keyId(KeyId.of(requiredText(node, "keyId")))
                .version(KeyVersion.of(requiredLong(node, "version")))
                .type(KeyType.valueOf(requiredText(node, "type")))
                .algorithm(AlgorithmId.of(requiredText(node, "algorithm")))
                .keyBits(requiredInt(node, "keyBits"))
                .state(KeyState.valueOf(requiredText(node, "state")))
                .usages(usages)
                .tenantId(requiredText(node, "tenantId"))
                .createdAt(Instant.parse(requiredText(node, "createdAt")))
                .activatedAt(nullableInstant(node, "activatedAt"))
                .expiresAt(nullableInstant(node, "expiresAt"))
                .rotationPolicy(rotation)
                .exportable(node.path("exportable").asBoolean(false))
                .usageCount(requiredLong(node, "usageCount"))
                .attributes(readStringMap(node.path("attributes")))
                .fingerprint(fingerprint)
                .build();
    }

    private static ObjectNode stringObject(Map<String, String> values) {
        ObjectNode node = MAPPER.createObjectNode();
        for (Map.Entry<String, String> entry : new TreeMap<>(values).entrySet()) {
            node.put(entry.getKey(), entry.getValue());
        }
        return node;
    }

    private static Map<String, String> readStringMap(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return Map.of();
        }
        if (!node.isObject()) {
            throw failure();
        }
        Map<String, String> values = new LinkedHashMap<>();
        node.properties().forEach(entry -> {
            if (!entry.getValue().isTextual()) {
                throw failure();
            }
            values.put(entry.getKey(), entry.getValue().asText());
        });
        return values;
    }

    private static String requiredText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isEmpty()) {
            throw failure();
        }
        return value.asText();
    }

    private static String nullableText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static long requiredLong(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.canConvertToLong()) {
            throw failure();
        }
        return value.asLong();
    }

    private static int requiredInt(JsonNode node, String field) {
        long value = requiredLong(node, field);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw failure();
        }
        return (int) value;
    }

    private static Instant nullableInstant(JsonNode node, String field) {
        String value = nullableText(node, field);
        return value == null ? null : Instant.parse(value);
    }

    private static KeyException failure() {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Malformed key record");
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Non-secret descriptor metadata plus the encoding of the stored material. */
    public record Metadata(KeyDescriptor descriptor, String materialFormat) {
        public Metadata {
            Objects.requireNonNull(descriptor, "descriptor");
            if (!KeyMaterialCodec.isKnownMaterialFormat(materialFormat)) {
                throw new IllegalArgumentException("Unknown material format");
            }
        }
    }
}