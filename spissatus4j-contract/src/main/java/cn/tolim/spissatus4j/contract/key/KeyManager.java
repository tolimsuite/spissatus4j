package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.List;
import java.util.Optional;

/**
 * Full key lifecycle API.
 *
 * <p>Lifecycle operations are policy-checked and audited by the implementation.
 * Illegal transitions are rejected. Private key material is never exported.</p>
 */
public interface KeyManager extends KeyMaterialAccess, AutoCloseable {

    KeyDescriptor generate(KeyGenerationRequest request, CallerContext caller);

    KeyDescriptor importKey(KeyImportRequest request, CallerContext caller);

    KeyDescriptor activate(KeyId keyId, KeyVersion version, CallerContext caller);

    KeyDescriptor rotate(KeyId keyId, CallerContext caller);

    KeyDescriptor deactivate(KeyId keyId, KeyVersion version, CallerContext caller);

    KeyDescriptor revoke(KeyId keyId, KeyVersion version, CallerContext caller, String reason);

    KeyDescriptor compromise(KeyId keyId, KeyVersion version, CallerContext caller, String reason);

    KeyDescriptor destroy(KeyId keyId, KeyVersion version, CallerContext caller);

    Optional<KeyDescriptor> describe(KeyId keyId, KeyVersion version, CallerContext caller);

    List<KeyDescriptor> list(String tenantId, CallerContext caller);

    List<KeyDescriptor> versions(KeyId keyId, CallerContext caller);

    /** Exports the public key (or certificate when available) in X.509 DER form. */
    byte[] exportPublicKey(KeyId keyId, KeyVersion version, CallerContext caller);

    byte[] wrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm, byte[] dek,
                   CallerContext caller);

    byte[] unwrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm, byte[] wrappedDek,
                     CallerContext caller);

    HealthStatus health();

    @Override
    void close();
}