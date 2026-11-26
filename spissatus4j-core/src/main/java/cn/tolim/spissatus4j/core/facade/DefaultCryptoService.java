package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.api.CryptoService;
import cn.tolim.spissatus4j.contract.audit.Alert;
import cn.tolim.spissatus4j.contract.audit.AlertSeverity;
import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.MetricNames;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.DerivedKey;
import cn.tolim.spissatus4j.contract.crypto.DigestRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.KdfRequest;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.MacRequest;
import cn.tolim.spissatus4j.contract.crypto.MacVerifyRequest;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.SignRequest;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.crypto.StreamEncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.StreamHeader;
import cn.tolim.spissatus4j.contract.crypto.VerifyRequest;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.exception.RuntimeSecurityException;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import javax.crypto.SecretKey;

/**
 * Facade implementation of all cryptographic operations.
 *
 * <p>Security invariants enforced here: fail-closed guard, compliance check,
 * policy evaluation, key-state and usage enforcement, nonce registration
 * before encryption, generic authentication failures, audit of security
 * operations and bounded metrics tags.</p>
 */
public final class DefaultCryptoService implements CryptoService {

    private static final System.Logger LOG = System.getLogger(DefaultCryptoService.class.getName());
    private static final int MAX_RANDOM_BYTES = 1024 * 1024;

    private final FacadeContext context;

    public DefaultCryptoService(FacadeContext context) {
        this.context = Objects.requireNonNull(context, "context");
    }

    // ------------------------------------------------------------------ encryption

    @Override
    public EncryptedData encrypt(EncryptRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("encrypt");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.AEAD
                    && info.family() != AlgorithmFamily.SYMMETRIC
                    && info.family() != AlgorithmFamily.ASYMMETRIC) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                        "Algorithm family cannot encrypt: " + request.algorithm().id());
            }
            enforceCompliance(info, Operation.ENCRYPT, request.caller(), request.keyId(),
                    request.keyVersion());
            KeyDescriptor key = authorizeKey(Operation.ENCRYPT, request.algorithm(),
                    request.keyId(), request.keyVersion(), KeyUsage.ENCRYPT, request.caller(),
                    request.attributes());
            EncryptedData data = doEncrypt(request, info, key);
            auditSuccess(AuditEventType.ENCRYPT, Operation.ENCRYPT, request.caller(),
                    request.algorithm(), key.version(), "Encryption completed");
            metricsSuccess(Operation.ENCRYPT, request.algorithm(), started);
            return data;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.ENCRYPT, Operation.ENCRYPT, request.caller(),
                    request.algorithm(), request.keyId(), null, e);
            metricsFailure(Operation.ENCRYPT, request.algorithm(), started);
            throw propagate(e, ErrorCode.ENCRYPTION_FAILED, "Encryption failed");
        }
    }

    private EncryptedData doEncrypt(EncryptRequest request, AlgorithmInfo info, KeyDescriptor key) {
        if (info.family() == AlgorithmFamily.ASYMMETRIC) {
            if (!request.aad().isEmpty()) {
                throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                        "AAD is not supported for asymmetric encryption");
            }
            PublicKey publicKey = publicKey(key, KeyUsage.ENCRYPT, request.caller());
            AsymmetricCipher cipher = requireAsymmetricCipher(request.algorithm());
            byte[] ciphertext;
            try {
                ciphertext = cipher.encrypt(publicKey, request.plaintext());
            } catch (CryptoException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "Encryption failed", e);
            }
            return EncryptedData.builder()
                    .algorithm(request.algorithm())
                    .keyId(key.keyId())
                    .keyVersion(key.version())
                    .nonce(Nonce.empty())
                    .ciphertext(ciphertext)
                    .tag(new byte[0])
                    .aad(AAD.empty())
                    .createdAt(context.clock().instant())
                    .build();
        }

        SecretKey secretKey = secretKey(key, KeyUsage.ENCRYPT, request.caller());
        AeadCipher cipher = requireAeadCipher(request.algorithm());
        Nonce nonce = freshNonce(request.algorithm(), cipher.nonceLength());
        registerNonce(request.algorithm(), nonce);
        AeadCipher.AeadResult result;
        try {
            result = cipher.encrypt(secretKey, request.plaintext(), nonce, request.aad());
        } catch (CryptoException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "Encryption failed", e);
        }
        if (result.tag().length != cipher.tagLength()) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Provider returned an unexpected authentication tag length");
        }
        return EncryptedData.builder()
                .algorithm(request.algorithm())
                .keyId(key.keyId())
                .keyVersion(key.version())
                .nonce(result.nonce())
                .ciphertext(result.ciphertext())
                .tag(result.tag())
                .aad(request.aad())
                .createdAt(context.clock().instant())
                .build();
    }

    // ------------------------------------------------------------------ decryption

    @Override
    public byte[] decrypt(DecryptRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("decrypt");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.AEAD
                    && info.family() != AlgorithmFamily.SYMMETRIC
                    && info.family() != AlgorithmFamily.ASYMMETRIC) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                        "Algorithm family cannot decrypt: " + request.algorithm().id());
            }
            enforceCompliance(info, Operation.DECRYPT, request.caller(), request.keyId(),
                    request.keyVersion() == null ? null : request.keyVersion().value());
            KeyDescriptor key = authorizeKey(Operation.DECRYPT, request.algorithm(),
                    request.keyId(), versionValue(request.keyVersion()), KeyUsage.DECRYPT,
                    request.caller(), Map.of());
            byte[] plaintext = doDecrypt(request, info, key);
            auditSuccess(AuditEventType.DECRYPT, Operation.DECRYPT, request.caller(),
                    request.algorithm(), key.version(), "Decryption completed");
            metricsSuccess(Operation.DECRYPT, request.algorithm(), started);
            return plaintext;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.DECRYPT, Operation.DECRYPT, request.caller(),
                    request.algorithm(), request.keyId(),
                    request.keyVersion(), e);
            metricsFailure(Operation.DECRYPT, request.algorithm(), started);
            if (e instanceof CryptoException) {
                throw e;
            }
            throw propagate(e, ErrorCode.DECRYPTION_FAILED, "Decryption failed");
        }
    }

    private byte[] doDecrypt(DecryptRequest request, AlgorithmInfo info, KeyDescriptor key) {
        if (info.family() == AlgorithmFamily.ASYMMETRIC) {
            if (request.ciphertext().length == 0) {
                throw new CryptoException(ErrorCode.INVALID_CIPHERTEXT, "Ciphertext is empty");
            }
            PrivateKey privateKey = privateKey(key, KeyUsage.DECRYPT, request.caller());
            AsymmetricCipher cipher = requireAsymmetricCipher(request.algorithm());
            try {
                return cipher.decrypt(privateKey, request.ciphertext());
            } catch (CryptoException e) {
                throw e;
            } catch (RuntimeException e) {
                throw CryptoException.authenticationFailed(request.algorithm());
            }
        }
        SecretKey secretKey = secretKey(key, KeyUsage.DECRYPT, request.caller());
        AeadCipher cipher = requireAeadCipher(request.algorithm());
        if (request.nonce().length() != cipher.nonceLength()
                || request.tag().length != cipher.tagLength()) {
            throw new CryptoException(ErrorCode.INVALID_CIPHERTEXT, "Invalid ciphertext");
        }
        try {
            return cipher.decrypt(secretKey, request.nonce(), request.ciphertext(), request.tag(),
                    request.aad());
        } catch (CryptoException e) {
            throw e;
        } catch (RuntimeException e) {
            throw CryptoException.authenticationFailed(request.algorithm());
        }
    }

    // ------------------------------------------------------------------ signatures

    @Override
    public byte[] sign(SignRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("sign");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.SIGNATURE) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm cannot sign");
            }
            enforceCompliance(info, Operation.SIGN, request.caller(), request.keyId(),
                    request.keyVersion());
            KeyDescriptor key = authorizeKey(Operation.SIGN, request.algorithm(),
                    request.keyId(), request.keyVersion(), KeyUsage.SIGN, request.caller(),
                    request.attributes());
            PrivateKey privateKey = privateKey(key, KeyUsage.SIGN, request.caller());
            SignatureFunction signature = requireSignature(request.algorithm());
            byte[] value;
            try {
                value = signature.sign(privateKey, request.message());
            } catch (CryptoException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "Signature operation failed", e);
            }
            auditSuccess(AuditEventType.SIGN, Operation.SIGN, request.caller(), request.algorithm(),
                    key.version(), "Signature created");
            metricsSuccess(Operation.SIGN, request.algorithm(), started);
            return value;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.SIGN, Operation.SIGN, request.caller(), request.algorithm(),
                    request.keyId(), null, e);
            metricsFailure(Operation.SIGN, request.algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "Signature operation failed");
        }
    }

    @Override
    public boolean verify(VerifyRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("verify");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.SIGNATURE) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm cannot verify");
            }
            enforceCompliance(info, Operation.VERIFY, request.caller(), request.keyId(),
                    request.keyVersion() == null ? null : request.keyVersion().value());
            PublicKey publicKey;
            KeyVersion version;
            if (request.publicKey() != null) {
                enforcePolicy(Operation.VERIFY, request.algorithm(), null, request.caller(), Map.of());
                publicKey = request.publicKey();
                version = request.keyVersion();
            } else {
                KeyDescriptor key = authorizeKey(Operation.VERIFY, request.algorithm(),
                        request.keyId(), versionValue(request.keyVersion()), KeyUsage.VERIFY,
                        request.caller(), Map.of());
                publicKey = publicKey(key, KeyUsage.VERIFY, request.caller());
                version = key.version();
            }
            SignatureFunction signature = requireSignature(request.algorithm());
            boolean valid;
            try {
                valid = signature.verify(publicKey, request.message(), request.signature());
            } catch (RuntimeException e) {
                valid = false;
            }
            auditVerify(request, version, valid);
            if (valid) {
                metricsSuccess(Operation.VERIFY, request.algorithm(), started);
            } else {
                metricsFailure(Operation.VERIFY, request.algorithm(), started);
            }
            return valid;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.VERIFY, Operation.VERIFY, request.caller(),
                    request.algorithm(), request.keyId(), null, e);
            metricsFailure(Operation.VERIFY, request.algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "Verification failed");
        }
    }

    private void auditVerify(VerifyRequest request, KeyVersion version, boolean valid) {
        AuditEvent.Builder builder = AuditEvent.builder(AuditEventType.VERIFY,
                        valid ? AuditSeverity.INFO : AuditSeverity.WARN,
                        valid ? AuditOutcome.SUCCESS : AuditOutcome.FAILURE)
                .caller(request.caller())
                .algorithm(request.algorithm())
                .keyId(request.keyId())
                .keyVersion(version)
                .operation(Operation.VERIFY)
                .message(valid ? "Signature verified" : "Signature verification failed")
                .detail("valid", Boolean.toString(valid));
        appendAudit(builder.build(), false);
    }

    // ------------------------------------------------------------------ digest & MAC

    @Override
    public byte[] digest(DigestRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("digest");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.HASH) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm is not a hash");
            }
            enforceCompliance(info, Operation.DIGEST, request.caller(), null, null);
            enforcePolicy(Operation.DIGEST, request.algorithm(), null, request.caller(), Map.of());
            HashFunction hash = requireHash(request.algorithm());
            byte[] result;
            try {
                result = hash.digest(request.data());
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "Digest operation failed", e);
            }
            metricsSuccess(Operation.DIGEST, request.algorithm(), started);
            return result;
        } catch (RuntimeException e) {
            metricsFailure(Operation.DIGEST, request.algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "Digest operation failed");
        }
    }

    @Override
    public byte[] mac(MacRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("mac");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.MAC) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm is not a MAC");
            }
            enforceCompliance(info, Operation.MAC, request.caller(), request.keyId(),
                    request.keyVersion());
            KeyDescriptor key = authorizeKey(Operation.MAC, request.algorithm(),
                    request.keyId(), request.keyVersion(), KeyUsage.MAC, request.caller(), Map.of());
            SecretKey secretKey = secretKey(key, KeyUsage.MAC, request.caller());
            MacFunction mac = requireMac(request.algorithm());
            byte[] value;
            try {
                value = mac.compute(secretKey, request.data());
            } catch (CryptoException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "MAC operation failed", e);
            }
            auditSuccess(AuditEventType.MAC, Operation.MAC, request.caller(), request.algorithm(),
                    key.version(), "MAC computed");
            metricsSuccess(Operation.MAC, request.algorithm(), started);
            return value;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.MAC, Operation.MAC, request.caller(), request.algorithm(),
                    request.keyId(), null, e);
            metricsFailure(Operation.MAC, request.algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "MAC operation failed");
        }
    }

    @Override
    public boolean verifyMac(MacVerifyRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        try {
            ready("verify-mac");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.MAC) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm is not a MAC");
            }
            enforceCompliance(info, Operation.VERIFY_MAC, request.caller(), request.keyId(),
                    request.keyVersion());
            KeyDescriptor key = authorizeKey(Operation.VERIFY_MAC, request.algorithm(),
                    request.keyId(), request.keyVersion(), KeyUsage.MAC, request.caller(), Map.of());
            SecretKey secretKey = secretKey(key, KeyUsage.MAC, request.caller());
            MacFunction mac = requireMac(request.algorithm());
            boolean valid;
            try {
                valid = mac.verify(secretKey, request.data(), request.expectedTag());
            } catch (RuntimeException e) {
                valid = false;
            }
            AuditEvent.Builder builder = AuditEvent.builder(AuditEventType.MAC,
                            valid ? AuditSeverity.INFO : AuditSeverity.WARN,
                            valid ? AuditOutcome.SUCCESS : AuditOutcome.FAILURE)
                    .caller(request.caller())
                    .algorithm(request.algorithm())
                    .keyId(request.keyId())
                    .keyVersion(key.version())
                    .operation(Operation.VERIFY_MAC)
                    .message(valid ? "MAC verified" : "MAC verification failed");
            appendAudit(builder.build(), false);
            if (valid) {
                metricsSuccess(Operation.VERIFY_MAC, request.algorithm(), started);
            } else {
                metricsFailure(Operation.VERIFY_MAC, request.algorithm(), started);
            }
            return valid;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.MAC, Operation.VERIFY_MAC, request.caller(),
                    request.algorithm(), request.keyId(), null, e);
            metricsFailure(Operation.VERIFY_MAC, request.algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "MAC verification failed");
        }
    }

    // ------------------------------------------------------------------ KDF

    @Override
    public DerivedKey deriveKey(KdfRequest request) {
        Objects.requireNonNull(request, "request");
        long started = System.nanoTime();
        char[] password = null;
        byte[] input = null;
        try {
            ready("derive-key");
            KdfParameters parameters = request.parameters();
            AlgorithmInfo info = requireAlgorithm(parameters.algorithm());
            if (info.family() != AlgorithmFamily.KDF) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION, "Algorithm is not a KDF");
            }
            enforceCompliance(info, Operation.DERIVE_KEY, request.caller(), null, null);
            enforcePolicy(Operation.DERIVE_KEY, parameters.algorithm(), null, request.caller(), Map.of());
            KdfFunction function = requireKdf(parameters.algorithm());
            password = request.password();
            input = request.inputKeyMaterial();
            byte[] derived;
            boolean needsRehash;
            try {
                derived = function.derive(input, password, request.salt(), parameters);
                needsRehash = function.needsRehash(parameters);
            } catch (CryptoException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "Key derivation failed", e);
            }
            if (derived == null || derived.length != parameters.outputBytes()) {
                Arrays.fill(derived == null ? new byte[0] : derived, (byte) 0);
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                        "Provider returned an unexpected derived key length");
            }
            DerivedKey result = new DerivedKey(parameters.algorithm(), derived, request.salt(),
                    parameters, needsRehash);
            Arrays.fill(derived, (byte) 0);
            auditSuccess(AuditEventType.KDF_DERIVE, Operation.DERIVE_KEY, request.caller(),
                    parameters.algorithm(), null, "Key derivation completed");
            metricsSuccess(Operation.DERIVE_KEY, parameters.algorithm(), started);
            return result;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.KDF_DERIVE, Operation.DERIVE_KEY, request.caller(),
                    request.parameters() == null ? null : request.parameters().algorithm(),
                    null, null, e);
            metricsFailure(Operation.DERIVE_KEY,
                    request.parameters() == null ? null : request.parameters().algorithm(), started);
            throw propagate(e, ErrorCode.PROVIDER_FAILURE, "Key derivation failed");
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (input != null) {
                Arrays.fill(input, (byte) 0);
            }
        }
    }

    // ------------------------------------------------------------------ random

    @Override
    public byte[] randomBytes(int length) {
        ready("random");
        if (length < 0 || length > MAX_RANDOM_BYTES) {
            throw new IllegalArgumentException("Invalid random byte length");
        }
        return context.randomService().nextBytes(length);
    }

    @Override
    public Nonce randomNonce(AlgorithmId algorithm) {
        ready("random-nonce");
        Objects.requireNonNull(algorithm, "algorithm");
        AlgorithmInfo info = requireAlgorithm(algorithm);
        if (info.nonceBytes() <= 0) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Algorithm does not define a nonce: " + algorithm.id());
        }
        return context.randomService().nextNonce(algorithm);
    }

    // ------------------------------------------------------------------ streams

    @Override
    public OutputStream openEncryptingStream(OutputStream output, StreamEncryptRequest request)
            throws IOException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(request, "request");
        try {
            ready("stream-encrypt");
            AlgorithmInfo info = requireAlgorithm(request.algorithm());
            if (info.family() != AlgorithmFamily.AEAD || info.nonceBytes() != 12) {
                throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                        "Streaming requires a 96-bit nonce AEAD algorithm");
            }
            enforceCompliance(info, Operation.STREAM_ENCRYPT, request.caller(), request.keyId(),
                    request.keyVersion());
            KeyDescriptor key = authorizeKey(Operation.STREAM_ENCRYPT, request.algorithm(),
                    request.keyId(), request.keyVersion(), KeyUsage.ENCRYPT, request.caller(),
                    request.attributes());
            AeadCipher cipher = requireAeadCipher(request.algorithm());
            if (cipher.nonceLength() != 12) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                        "Stream cipher requires 12-byte nonces");
            }
            SecretKey secretKey = secretKey(key, KeyUsage.ENCRYPT, request.caller());
            Nonce nonce = freshNonce(request.algorithm(), 12);
            registerNonce(request.algorithm(), nonce);
            StreamHeader header = new StreamHeader(StreamHeader.CURRENT_VERSION, request.algorithm(),
                    key.keyId(), key.version(), nonce, request.chunkSize(), request.aad(),
                    context.clock().instant(), request.attributes());
            StreamCipherService streams = requireStreamCipherService();
            streams.writeHeader(output, header);
            OutputStream encrypting = streams.openEncrypting(output, header, cipher, secretKey);
            auditStream(AuditEventType.STREAM_STARTED, Operation.STREAM_ENCRYPT, request.caller(),
                    request.algorithm(), key.version(), "Encrypting stream opened");
            return new AuditedOutputStream(encrypting, request.caller(), header,
                    Operation.STREAM_ENCRYPT);
        } catch (IOException e) {
            throw e;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.STREAM_STARTED, Operation.STREAM_ENCRYPT, request.caller(),
                    request.algorithm(), request.keyId(), null, e);
            throw propagate(e, ErrorCode.ENCRYPTION_FAILED, "Stream open failed");
        }
    }

    @Override
    public InputStream openDecryptingStream(InputStream input, CallerContext caller)
            throws IOException {
        return openDecryptingStream(input, caller, 0);
    }

    @Override
    public InputStream openDecryptingStream(InputStream input, CallerContext caller, long chunksToSkip)
            throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(caller, "caller");
        if (chunksToSkip < 0) {
            throw new IllegalArgumentException("chunksToSkip must not be negative");
        }
        try {
            ready("stream-decrypt");
            StreamCipherService streams = requireStreamCipherService();
            StreamHeader header = streams.readHeader(input);
            if (header.version() != StreamHeader.CURRENT_VERSION) {
                throw new CryptoException(ErrorCode.STREAM_CORRUPTED,
                        "Unsupported stream version");
            }
            AlgorithmInfo info = requireAlgorithm(header.algorithm());
            if (info.family() != AlgorithmFamily.AEAD || info.nonceBytes() != 12) {
                throw new CryptoException(ErrorCode.STREAM_CORRUPTED,
                        "Stream algorithm is not supported");
            }
            enforceCompliance(info, Operation.STREAM_DECRYPT, caller, header.keyId(),
                    header.keyVersion().value());
            KeyDescriptor key = authorizeKey(Operation.STREAM_DECRYPT, header.algorithm(),
                    header.keyId(), header.keyVersion().value(), KeyUsage.DECRYPT, caller, Map.of());
            SecretKey secretKey = secretKey(key, KeyUsage.DECRYPT, caller);
            AeadCipher cipher = requireAeadCipher(header.algorithm());
            if (cipher.nonceLength() != 12) {
                throw new CryptoException(ErrorCode.STREAM_CORRUPTED,
                        "Stream cipher requires 12-byte nonces");
            }
            if (chunksToSkip > 0) {
                streams.skipChunks(input, header, chunksToSkip);
            }
            InputStream decrypting = streams.openDecrypting(input, header, cipher, secretKey,
                    chunksToSkip);
            auditStream(AuditEventType.STREAM_STARTED, Operation.STREAM_DECRYPT, caller,
                    header.algorithm(), key.version(), "Decrypting stream opened");
            return new AuditedInputStream(decrypting, caller, header, Operation.STREAM_DECRYPT);
        } catch (IOException e) {
            throw e;
        } catch (RuntimeException e) {
            auditFailure(AuditEventType.STREAM_STARTED, Operation.STREAM_DECRYPT, caller, null,
                    null, null, e);
            throw propagate(e, ErrorCode.DECRYPTION_FAILED, "Stream open failed");
        }
    }

    private final class AuditedOutputStream extends FilterOutputStream {
        private final CallerContext caller;
        private final StreamHeader header;
        private final Operation operation;
        private final AtomicBoolean finished = new AtomicBoolean();
        private final AtomicBoolean failed = new AtomicBoolean();
        private long bytes;

        private AuditedOutputStream(OutputStream out, CallerContext caller, StreamHeader header,
                                    Operation operation) {
            super(out);
            this.caller = caller;
            this.header = header;
            this.operation = operation;
        }

        @Override
        public void write(int b) throws IOException {
            try {
                context.guard().ensureOperational("stream-encrypt");
                out.write(b);
                bytes++;
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                context.guard().ensureOperational("stream-encrypt");
                out.write(b, off, len);
                bytes += len;
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        @Override
        public void flush() throws IOException {
            try {
                out.flush();
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        @Override
        public void close() throws IOException {
            try {
                out.flush();
                out.close();
                finish();
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        private void finish() {
            if (finished.compareAndSet(false, true) && !failed.get()) {
                auditStream(AuditEventType.STREAM_COMPLETED, operation, caller,
                        header.algorithm(), header.keyVersion(), "Encrypting stream completed");
                metricsStreamBytes(operation, header.algorithm(), bytes);
            }
        }

        private void fail(Exception e) {
            if (failed.compareAndSet(false, true)) {
                auditStream(AuditEventType.STREAM_FAILED, operation, caller,
                        header.algorithm(), header.keyVersion(), "Encrypting stream failed");
                metricsFailure(operation, header.algorithm(), 0);
            }
        }
    }

    private final class AuditedInputStream extends FilterInputStream {
        private final CallerContext caller;
        private final StreamHeader header;
        private final Operation operation;
        private final AtomicBoolean finished = new AtomicBoolean();
        private final AtomicBoolean failed = new AtomicBoolean();
        private final AtomicBoolean eofReached = new AtomicBoolean();
        private long bytes;

        private AuditedInputStream(InputStream in, CallerContext caller, StreamHeader header,
                                   Operation operation) {
            super(in);
            this.caller = caller;
            this.header = header;
            this.operation = operation;
        }

        @Override
        public int read() throws IOException {
            try {
                context.guard().ensureOperational("stream-decrypt");
                int value = in.read();
                if (value < 0) {
                    eofReached.set(true);
                    finish();
                } else {
                    bytes++;
                }
                return value;
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            try {
                context.guard().ensureOperational("stream-decrypt");
                int read = in.read(b, off, len);
                if (read < 0) {
                    eofReached.set(true);
                    finish();
                } else {
                    bytes += read;
                }
                return read;
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        @Override
        public void close() throws IOException {
            try {
                in.close();
                if (eofReached.get()) {
                    finish();
                } else if (!finished.get() && !failed.get()) {
                    fail(new IOException("Stream closed before authenticated end"));
                }
            } catch (IOException | RuntimeException e) {
                fail(e);
                throw e;
            }
        }

        private void finish() {
            if (finished.compareAndSet(false, true) && !failed.get()) {
                auditStream(AuditEventType.STREAM_COMPLETED, operation, caller,
                        header.algorithm(), header.keyVersion(), "Decrypting stream completed");
                metricsStreamBytes(operation, header.algorithm(), bytes);
            }
        }

        private void fail(Exception e) {
            if (failed.compareAndSet(false, true)) {
                auditStream(AuditEventType.STREAM_FAILED, operation, caller,
                        header.algorithm(), header.keyVersion(), "Decrypting stream failed");
                metricsFailure(operation, header.algorithm(), 0);
            }
        }
    }

    // ------------------------------------------------------------------ policy / keys / engines

    private void ready(String operation) {
        context.guard().ensureOperational(operation);
    }

    private AlgorithmInfo requireAlgorithm(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        AlgorithmInfo info = algorithm.info();
        if (info.family() == AlgorithmFamily.UNKNOWN || !algorithm.isKnown()) {
            throw new CryptoException(ErrorCode.ALGORITHM_UNKNOWN,
                    "Unknown algorithm: " + algorithm.id());
        }
        return info;
    }

    private void enforceCompliance(AlgorithmInfo info, Operation operation, CallerContext caller,
                                   KeyId keyId, Long keyVersionValue) {
        if (context.complianceMode().allows(info)) {
            return;
        }
        auditDenial(operation, info.id(), keyId,
                keyVersionValue == null ? null : KeyVersion.of(keyVersionValue), caller,
                ReasonCodes.COMPLIANCE_MODE_VIOLATION, "compliance");
        throw new PolicyException(ErrorCode.COMPLIANCE_MODE_DENIED,
                context.complianceMode().violationReason(info));
    }

    /**
     * Authorizes and resolves a key: read-only descriptor lookup -> policy
     * decision (single token/audit) -> stateful resolution (rotation/usage).
     */
    private KeyDescriptor authorizeKey(Operation operation, AlgorithmId algorithm, KeyId keyId,
                                       Long version, KeyUsage usage, CallerContext caller,
                                       Map<String, String> attributes) {
        KeyDescriptor peeked;
        try {
            peeked = context.keyManager().peekForUse(keyId, version, usage, caller);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key resolution failed", e);
        }
        enforcePolicy(operation, algorithm, peeked, caller, attributes);
        KeyDescriptor resolved = resolveKey(keyId, version, usage, caller);
        requireCompatibleKey(resolved, algorithm);
        return resolved;
    }

    private KeyDescriptor resolveKey(KeyId keyId, Long version, KeyUsage usage, CallerContext caller) {
        try {
            return context.keyManager().resolveForUse(keyId, version, usage, caller);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key resolution failed", e);
        }
    }

    private SecretKey secretKey(KeyDescriptor key, KeyUsage usage, CallerContext caller) {
        try {
            return context.keyManager().secretKey(key.keyId(), key.version(), usage, caller);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key material access failed", e);
        }
    }

    private PrivateKey privateKey(KeyDescriptor key, KeyUsage usage, CallerContext caller) {
        try {
            return context.keyManager().privateKey(key.keyId(), key.version(), usage, caller);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key material access failed", e);
        }
    }

    private PublicKey publicKey(KeyDescriptor key, KeyUsage usage, CallerContext caller) {
        try {
            return context.keyManager().publicKey(key.keyId(), key.version(), usage, caller);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key material access failed", e);
        }
    }

    private PolicyDecision enforcePolicy(Operation operation, AlgorithmId algorithm, KeyDescriptor key,
                                         CallerContext caller, Map<String, String> attributes) {
        PolicyRequest.Builder builder = PolicyRequest.builder(operation, caller)
                .algorithm(algorithm)
                .attributes(attributes);
        if (key != null) {
            builder.key(key).keyId(key.keyId()).keyVersion(key.version());
        }
        PolicyDecision decision;
        try {
            decision = context.policyEngine().evaluate(builder.build());
        } catch (RuntimeException e) {
            throw new PolicyException(ErrorCode.POLICY_UNAVAILABLE, "Policy evaluation unavailable");
        }
        if (decision == null) {
            decision = PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "Policy evaluation unavailable", "fail-closed");
        }
        if (decision.denied()) {
            auditDenial(operation, algorithm, key == null ? null : key.keyId(),
                    key == null ? null : key.version(), caller, decision.reasonCode(),
                    decision.policyId());
            throw policyException(decision);
        }
        if (decision.warned()) {
            AuditEvent.Builder audit = AuditEvent.builder(AuditEventType.POLICY_WARNING,
                            AuditSeverity.WARN, AuditOutcome.SUCCESS)
                    .caller(caller)
                    .algorithm(algorithm)
                    .operation(operation)
                    .keyId(key == null ? null : key.keyId())
                    .keyVersion(key == null ? null : key.version())
                    .message(context.redactor().redact(decision.message()))
                    .detail("reason", decision.reasonCode())
                    .detail("policy", decision.policyId());
            appendAudit(audit.build(), false);
            metricsIncrement(MetricNames.POLICY_WARNINGS,
                    Map.of("reason", decision.reasonCode()));
        }
        return decision;
    }

    private static PolicyException policyException(PolicyDecision decision) {
        ErrorCode code = switch (decision.reasonCode()) {
            case ReasonCodes.ANONYMOUS_CALLER, ReasonCodes.CALLER_NOT_AUTHORIZED,
                 ReasonCodes.ACCESS_DENIED -> ErrorCode.ACCESS_DENIED;
            case ReasonCodes.TENANT_MISMATCH, ReasonCodes.CROSS_TENANT_DENIED -> ErrorCode.TENANT_VIOLATION;
            case ReasonCodes.RATE_LIMITED -> ErrorCode.RATE_LIMITED;
            case ReasonCodes.QUOTA_EXCEEDED -> ErrorCode.QUOTA_EXCEEDED;
            case ReasonCodes.POLICY_UNAVAILABLE, ReasonCodes.POLICY_SOURCE_UNAVAILABLE ->
                    ErrorCode.POLICY_UNAVAILABLE;
            case ReasonCodes.COMPLIANCE_MODE_VIOLATION, ReasonCodes.FIPS_MODE_VIOLATION,
                 ReasonCodes.GM_MODE_VIOLATION -> ErrorCode.COMPLIANCE_VIOLATION;
            case ReasonCodes.ALGORITHM_UNKNOWN, ReasonCodes.ALGORITHM_PROHIBITED,
                 ReasonCodes.ALGORITHM_NOT_ALLOWED -> ErrorCode.ALGORITHM_PROHIBITED;
            case ReasonCodes.ALGORITHM_EXPERIMENTAL -> ErrorCode.ALGORITHM_EXPERIMENTAL;
            case ReasonCodes.MIN_KEY_BITS -> ErrorCode.MIN_KEY_BITS_VIOLATION;
            case ReasonCodes.KEY_USAGE_MISMATCH -> ErrorCode.KEY_USAGE_VIOLATION;
            case ReasonCodes.KEY_NOT_ACTIVE, ReasonCodes.KEY_EXPIRED -> ErrorCode.KEY_NOT_ACTIVE;
            default -> ErrorCode.POLICY_DENIED;
        };
        return new PolicyException(code, decision.message());
    }

    private void requireCompatibleKey(KeyDescriptor key, AlgorithmId algorithm) {
        KeyType type = key.type();
        boolean compatible = switch (algorithm.family()) {
            case AEAD, SYMMETRIC -> isSymmetricType(type, algorithm);
            case MAC -> isMacType(type, algorithm);
            case ASYMMETRIC -> switch (algorithm.id()) {
                case "RSA-OAEP", "RSA-PKCS1-V1.5" -> type == KeyType.RSA;
                case "ECIES" -> type == KeyType.EC;
                case "SM2" -> type == KeyType.SM2;
                case "ML-KEM-768" -> type == KeyType.KEM || type == KeyType.RAW;
                default -> true;
            };
            case SIGNATURE -> switch (algorithm.id()) {
                case "RSA-PSS", "RSA-PKCS1-V1.5-SIGNATURE", "DSA" -> type == KeyType.RSA
                        || type == KeyType.RAW;
                case "ECDSA-P256", "ECDSA-P384" -> type == KeyType.EC;
                case "ED25519" -> type == KeyType.ED25519;
                case "ED448" -> type == KeyType.ED448;
                case "SM2-SIGNATURE" -> type == KeyType.SM2;
                case "ML-DSA-65" -> type == KeyType.KEM || type == KeyType.RAW;
                default -> true;
            };
            default -> true;
        };
        if (!compatible) {
            throw new KeyException(ErrorCode.KEY_USAGE_VIOLATION,
                    "Key type is not compatible with the requested algorithm");
        }
    }

    private static boolean isSymmetricType(KeyType type, AlgorithmId algorithm) {
        if (algorithm.id().startsWith("SM4")) {
            return type == KeyType.SM4 || type == KeyType.SYMMETRIC || type == KeyType.RAW;
        }
        if (algorithm.id().startsWith("AES") || algorithm == AlgorithmId.CHACHA20_POLY1305) {
            return type == KeyType.AES || type == KeyType.SYMMETRIC || type == KeyType.RAW;
        }
        if (algorithm.id().startsWith("3DES") || algorithm.id().startsWith("DES")
                || algorithm == AlgorithmId.RC4) {
            return type == KeyType.SYMMETRIC || type == KeyType.RAW;
        }
        return true;
    }

    private static boolean isMacType(KeyType type, AlgorithmId algorithm) {
        if (algorithm == AlgorithmId.HMAC_SM3) {
            return type == KeyType.HMAC || type == KeyType.SM4 || type == KeyType.SYMMETRIC
                    || type == KeyType.RAW;
        }
        if (algorithm == AlgorithmId.CMAC_AES) {
            return type == KeyType.AES || type == KeyType.SYMMETRIC || type == KeyType.RAW;
        }
        return type == KeyType.HMAC || type == KeyType.SYMMETRIC || type == KeyType.RAW;
    }

    private Nonce freshNonce(AlgorithmId algorithm, int length) {
        if (length < 1 || length > 64) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Provider reported an invalid nonce length");
        }
        int expected = algorithm.info().nonceBytes();
        if (expected > 0 && expected != length) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Provider nonce length does not match the algorithm catalog");
        }
        byte[] bytes = context.randomService().nextBytes(length);
        try {
            return Nonce.of(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private void registerNonce(AlgorithmId algorithm, Nonce nonce) {
        boolean reused;
        try {
            reused = context.nonceReuseDetector().register(algorithm, nonce);
        } catch (RuntimeException e) {
            raiseAlert(AlertSeverity.CRITICAL, "NONCE_TRACKER_UNAVAILABLE",
                    "Nonce reuse detector unavailable", Map.of("algorithm", algorithm.id()));
            throw new RuntimeSecurityException(ErrorCode.RUNTIME_UNAVAILABLE,
                    "Nonce reuse detector unavailable", e);
        }
        if (reused) {
            metricsIncrement(MetricNames.NONCE_REUSE, Map.of("algorithm", algorithm.id()));
            raiseAlert(AlertSeverity.CRITICAL, "NONCE_REUSE",
                    "Nonce reuse detected", Map.of("algorithm", algorithm.id()));
            AuditEvent.Builder audit = AuditEvent.builder(AuditEventType.NONCE_REUSE,
                            AuditSeverity.CRITICAL, AuditOutcome.FAILURE)
                    .callerId("system")
                    .tenantId("system")
                    .algorithm(algorithm)
                    .message("Nonce reuse detected");
            appendAudit(audit.build(), false);
            throw new RuntimeSecurityException(ErrorCode.NONCE_REUSE,
                    "Nonce reuse detected for algorithm " + algorithm.id());
        }
    }

    private StreamCipherService requireStreamCipherService() {
        StreamCipherService service = context.streamCipherService();
        if (service == null) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "No StreamCipherService is installed");
        }
        return service;
    }

    private AeadCipher requireAeadCipher(AlgorithmId algorithm) {
        return engine(algorithm, "AEAD cipher", provider -> provider.aeadCipher(algorithm));
    }

    private AsymmetricCipher requireAsymmetricCipher(AlgorithmId algorithm) {
        return engine(algorithm, "asymmetric cipher", provider -> provider.asymmetricCipher(algorithm));
    }

    private HashFunction requireHash(AlgorithmId algorithm) {
        return engine(algorithm, "hash function", provider -> provider.hash(algorithm));
    }

    private MacFunction requireMac(AlgorithmId algorithm) {
        return engine(algorithm, "MAC function", provider -> provider.mac(algorithm));
    }

    private SignatureFunction requireSignature(AlgorithmId algorithm) {
        return engine(algorithm, "signature function", provider -> provider.signature(algorithm));
    }

    private KdfFunction requireKdf(AlgorithmId algorithm) {
        return engine(algorithm, "KDF function", provider -> provider.kdf(algorithm));
    }

    private <T> T engine(AlgorithmId algorithm, String kind, Function<AlgorithmProvider, T> factory) {
        for (AlgorithmProvider provider : context.providers()) {
            if (context.complianceMode() == cn.tolim.spissatus4j.contract.compliance.ComplianceMode.FIPS
                    && !provider.fipsCapable()) {
                continue;
            }
            boolean supports;
            try {
                supports = provider.supports(algorithm);
            } catch (RuntimeException e) {
                continue;
            }
            if (!supports) {
                continue;
            }
            try {
                T engine = factory.apply(provider);
                if (engine != null) {
                    return engine;
                }
            } catch (CryptoException e) {
                if (e.errorCode() == ErrorCode.ALGORITHM_UNSUPPORTED) {
                    continue;
                }
                throw e;
            } catch (RuntimeException e) {
                throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                        "Provider failed to create " + kind, e);
            }
        }
        throw CryptoException.unsupported(algorithm);
    }

    // ------------------------------------------------------------------ audit / metrics / alerts

    private void auditSuccess(AuditEventType type, Operation operation, CallerContext caller,
                              AlgorithmId algorithm, KeyVersion version, String message) {
        AuditEvent.Builder builder = AuditEvent.builder(type, AuditSeverity.INFO, AuditOutcome.SUCCESS)
                .caller(caller)
                .algorithm(algorithm)
                .keyVersion(version)
                .operation(operation)
                .message(message);
        appendAudit(builder.build(), true);
    }

    private void auditStream(AuditEventType type, Operation operation, CallerContext caller,
                             AlgorithmId algorithm, KeyVersion version, String message) {
        AuditEvent.Builder builder = AuditEvent.builder(type, AuditSeverity.INFO, AuditOutcome.SUCCESS)
                .caller(caller)
                .algorithm(algorithm)
                .keyVersion(version)
                .operation(operation)
                .message(message);
        appendAudit(builder.build(), false);
    }

    private void auditDenial(Operation operation, AlgorithmId algorithm, KeyId keyId,
                             KeyVersion version, CallerContext caller, String reason, String policy) {
        AuditEvent.Builder builder = AuditEvent.builder(AuditEventType.POLICY_DENIED,
                        AuditSeverity.WARN, AuditOutcome.DENIED)
                .caller(caller)
                .algorithm(algorithm)
                .keyId(keyId)
                .keyVersion(version)
                .operation(operation)
                .message("Operation denied")
                .detail("reason", reason)
                .detail("policy", policy);
        appendAudit(builder.build(), false);
        metricsIncrement(MetricNames.POLICY_DENIALS, Map.of("reason", reason));
    }

    private void auditFailure(AuditEventType type, Operation operation, CallerContext caller,
                              AlgorithmId algorithm, KeyId keyId, KeyVersion version,
                              RuntimeException failure) {
        if (alreadyAudited(failure)) {
            return;
        }
        AuditEvent.Builder builder = AuditEvent.builder(type, AuditSeverity.ERROR, AuditOutcome.FAILURE)
                .caller(caller)
                .algorithm(algorithm)
                .keyId(keyId)
                .keyVersion(version)
                .operation(operation)
                .message("Operation failed")
                .detail("errorCode", failure instanceof SpissatusException se
                        ? se.errorCode().name() : "INTERNAL_ERROR");
        appendAudit(builder.build(), false);
    }

    private static boolean alreadyAudited(RuntimeException failure) {
        if (!(failure instanceof SpissatusException se)) {
            return false;
        }
        return switch (se.errorCode()) {
            case POLICY_DENIED, ACCESS_DENIED, TENANT_VIOLATION, RATE_LIMITED, QUOTA_EXCEEDED,
                 COMPLIANCE_VIOLATION, COMPLIANCE_MODE_DENIED, NONCE_REUSE -> true;
            default -> false;
        };
    }

    private void appendAudit(AuditEvent event, boolean enforce) {
        boolean failed = false;
        try {
            context.auditTrail().append(event);
            if (context.auditTrail().health() != cn.tolim.spissatus4j.contract.runtime.HealthStatus.UP) {
                failed = true;
            }
        } catch (RuntimeException e) {
            failed = true;
        }
        if (failed) {
            metricsIncrement(MetricNames.AUDIT_WRITE_FAILURES, Map.of());
            raiseAlert(AlertSeverity.HIGH, "AUDIT_WRITE_FAILURE",
                    "Audit trail write failed", Map.of());
            LOG.log(System.Logger.Level.WARNING, "Audit trail write failed");
            if (enforce && context.auditFailureFailsOperation()) {
                throw new AuditException(ErrorCode.AUDIT_FAILURE, "Audit trail write failed");
            }
        }
    }

    private static String algorithmTag(AlgorithmId algorithm) {
        if (algorithm == null) {
            return "none";
        }
        return algorithm.isKnown() ? algorithm.id() : "unknown";
    }

    private void metricsSuccess(Operation operation, AlgorithmId algorithm, long startedNanos) {
        metricsIncrement(MetricNames.OPERATIONS, Map.of(
                "operation", operation.name(),
                "algorithm", algorithmTag(algorithm),
                "outcome", "success"));
        if (startedNanos > 0) {
            double seconds = (System.nanoTime() - startedNanos) / 1_000_000_000d;
            try {
                context.metricsRecorder().observe(MetricNames.OPERATION_LATENCY, seconds,
                        Map.of("operation", operation.name()));
            } catch (RuntimeException ignored) {
                // metrics must not break operations
            }
        }
    }

    private void metricsFailure(Operation operation, AlgorithmId algorithm, long startedNanos) {
        metricsIncrement(MetricNames.OPERATIONS, Map.of(
                "operation", operation.name(),
                "algorithm", algorithmTag(algorithm),
                "outcome", "failure"));
    }

    private void metricsStreamBytes(Operation operation, AlgorithmId algorithm, long bytes) {
        try {
            context.metricsRecorder().increment(MetricNames.STREAM_BYTES,
                    Map.of("operation", operation.name(),
                            "algorithm", algorithm == null ? "none" : algorithm.id()), bytes);
        } catch (RuntimeException ignored) {
        }
    }

    private void metricsIncrement(String name, Map<String, String> tags) {
        try {
            context.metricsRecorder().increment(name, tags);
        } catch (RuntimeException ignored) {
            // instrumentation never fails a cryptographic operation
        }
    }

    private void raiseAlert(AlertSeverity severity, String code, String message,
                            Map<String, String> tags) {
        Alert alert = new Alert(Instant.now(), severity, code, message, tags);
        for (AlertSink sink : context.alertSinks()) {
            try {
                sink.raise(alert);
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.WARNING, "Alert sink failed: {0}", sink.sinkId());
            }
        }
    }

    private static RuntimeException propagate(RuntimeException failure, ErrorCode code, String message) {
        if (failure instanceof SpissatusException) {
            return failure;
        }
        return new CryptoException(code, message, failure);
    }

    private static Long versionValue(KeyVersion version) {
        return version == null ? null : version.value();
    }

    // Visible for tests.
    RuntimeState state() {
        return context.guard().state();
    }
}