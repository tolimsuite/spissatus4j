package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Internal-facing key material access used by the facade and the stream layer.
 *
 * <p>Business code should depend on {@link KeyManager} only and must never
 * extract a DEK. Implementations must enforce key state, tenant isolation and
 * usage isolation on every call and must never cache plaintext private keys in
 * a static field.</p>
 */
public interface KeyMaterialAccess {

    /**
     * Resolves the descriptor that should be used for a new operation,
     * performing lazy rotation when the active version is due. A null version
     * means "newest active version".
     */
    KeyDescriptor resolveForUse(KeyId keyId, Long requestedVersion, KeyUsage usage, CallerContext caller);

    /**
     * Read-only descriptor lookup used by the facade to authorize a request
     * before any usage counter is incremented or lazy rotation is triggered.
     * The default implementation delegates to {@link #resolveForUse}; key
     * managers that can separate lookup from admission should override it.
     */
    default KeyDescriptor peekForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                     CallerContext caller) {
        return resolveForUse(keyId, requestedVersion, usage, caller);
    }

    SecretKey secretKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);

    PrivateKey privateKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);

    PublicKey publicKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);
}