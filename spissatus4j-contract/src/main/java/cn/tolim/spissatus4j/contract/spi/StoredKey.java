package cn.tolim.spissatus4j.contract.spi;

import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import java.util.Map;
import java.util.Objects;

/**
 * Provider-neutral stored key record. Material must be encrypted at rest by
 * providers that write to persistent storage. A destroyed tombstone has an
 * empty material array.
 *
 * @param descriptor non-secret metadata
 * @param material encoded material (RAW, PKCS8 or X509)
 * @param materialFormat RAW, PKCS8 or X509
 * @param encrypted whether the material is encrypted by the provider
 * @param attributes provider-specific non-sensitive attributes
 */
public record StoredKey(KeyDescriptor descriptor, byte[] material, String materialFormat,
                        boolean encrypted, Map<String, String> attributes) {

    public StoredKey {
        Objects.requireNonNull(descriptor, "descriptor");
        material = Objects.requireNonNull(material, "material").clone();
        materialFormat = Objects.requireNonNull(materialFormat, "materialFormat");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    @Override
    public byte[] material() {
        return material.clone();
    }

    @Override
    public String toString() {
        return "StoredKey[keyId=" + descriptor.keyId() + ", version=" + descriptor.version()
                + ", format=" + materialFormat + ", materialLength=" + material.length + "]";
    }
}