package cn.tolim.spissatus4j.contract.envelope;

import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.Map;

/**
 * Envelope creation, serialization, parsing and validation. Decoding is
 * fail-closed; unknown versions are rejected unless the version policy
 * explicitly supports them.
 */
public interface EnvelopeService {

    Envelope create(EncryptedData data, Map<String, String> attributes);

    /**
     * Creates a v2 envelope whose metadata is bound to the ciphertext through
     * the supplied header hash. Implementations that cannot produce bound
     * envelopes must fail closed.
     */
    default Envelope createBound(EncryptedData data, byte[] headerHash,
                                 Map<String, String> attributes) {
        throw new EnvelopeException(ErrorCode.UNSUPPORTED_OPERATION,
                "Bound envelope creation is not supported");
    }

    byte[] encode(Envelope envelope, EnvelopeFormat format);

    Envelope decode(byte[] encoded);

    String encodeText(Envelope envelope, EnvelopeFormat format, BinaryEncoding encoding);

    Envelope decodeText(String text);

    void validate(Envelope envelope);

    boolean supportsVersion(int version);

    VersionPolicy versionPolicy();
}