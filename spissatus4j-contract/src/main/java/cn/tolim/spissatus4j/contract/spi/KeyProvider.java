package cn.tolim.spissatus4j.contract.spi;

import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.List;
import java.util.Optional;

/**
 * Persistent key storage (memory, file, KeyStore, environment, KMS/Vault/HSM
 * adapter). Implementations must not write key material in plaintext.
 */
public interface KeyProvider {

    String providerId();

    Optional<StoredKey> load(KeyId keyId, KeyVersion version);

    void save(StoredKey storedKey);

    boolean delete(KeyId keyId, KeyVersion version);

    List<StoredKey> list(String tenantId);

    HealthStatus health();

    default void close() {
    }
}