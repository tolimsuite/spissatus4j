package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeBinding;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.MessageDigest;
import java.util.Objects;

/** Verifies v2 envelope metadata binding before any decryption is attempted. */
final class EnvelopeMetadataVerifier {

    private static final String GENERIC_FAILURE = "Envelope metadata authentication failed";

    private EnvelopeMetadataVerifier() {
    }

    static boolean isBound(Envelope envelope) {
        return envelope.version() >= 2;
    }

    static void verifyBound(Envelope envelope) {
        Objects.requireNonNull(envelope, "envelope");
        if (!isBound(envelope)) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope is not a bound envelope");
        }
        byte[] stored = envelope.headerHash();
        if (stored.length != EnvelopeBinding.HEADER_HASH_BYTES) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope header binding is missing or invalid");
        }
        byte[] computed;
        try {
            computed = EnvelopeBinding.headerHash(envelope);
        } catch (RuntimeException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_BINDING_MISMATCH, GENERIC_FAILURE);
        }
        if (!MessageDigest.isEqual(stored, computed)) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_BINDING_MISMATCH, GENERIC_FAILURE);
        }
    }

    static AAD effectiveAad(Envelope envelope) {
        try {
            return EnvelopeBinding.effectiveAad(envelope.aad(), envelope.headerHash());
        } catch (IllegalArgumentException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope authenticated data is invalid");
        }
    }
}