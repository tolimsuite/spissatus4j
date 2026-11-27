package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
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

    /**
     * Options-aware variant of {@link #resolveForUse}. Managers that cannot
     * represent relaxed state admission must reject the permissive option
     * instead of silently ignoring it; the default implementation does so.
     */
    default KeyDescriptor resolveForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                        CallerContext caller, KeyUseOptions options) {
        requireSupported(options);
        return resolveForUse(keyId, requestedVersion, usage, caller);
    }

    /** Options-aware variant of {@link #peekForUse}. */
    default KeyDescriptor peekForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                     CallerContext caller, KeyUseOptions options) {
        requireSupported(options);
        return peekForUse(keyId, requestedVersion, usage, caller);
    }

    SecretKey secretKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);

    /** Options-aware material access used by the encryption path. */
    default SecretKey secretKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                                CallerContext caller, KeyUseOptions options) {
        requireSupported(options);
        return secretKey(keyId, version, usage, caller);
    }

    PrivateKey privateKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);

    /** Options-aware material access used by signature/decryption paths. */
    default PrivateKey privateKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                                  CallerContext caller, KeyUseOptions options) {
        requireSupported(options);
        return privateKey(keyId, version, usage, caller);
    }

    PublicKey publicKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller);

    /** Options-aware material access used by the asymmetric encryption path. */
    default PublicKey publicKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                                CallerContext caller, KeyUseOptions options) {
        requireSupported(options);
        return publicKey(keyId, version, usage, caller);
    }

    /**
     * Enumerates minimal, non-secret candidates that may serve {@code usage}
     * for the caller's own tenant, bounded by {@code limit}.
     *
     * <p>This is an advisory, non-authoritative facility for unified key
     * selection. It must not evaluate the policy engine, rotate keys, consume
     * rate limits or return another tenant's keys, and it returns no key
     * attributes or other metadata gated by the read policy. The single
     * authoritative decision is made later on the selected key. The default
     * returns an empty list so implementations without enumeration keep
     * explicit key selection only.</p>
     */
    default List<KeySelectionCandidate> candidateKeys(KeyUsage usage, CallerContext caller,
                                                      int limit) {
        return List.of();
    }

    private static void requireSupported(KeyUseOptions options) {
        if (options != null && options.allowDeactivatedEncryption()) {
            throw new ConfigurationException(ErrorCode.UNSUPPORTED_OPERATION,
                    "This key manager does not support deactivated-key encryption");
        }
    }
}