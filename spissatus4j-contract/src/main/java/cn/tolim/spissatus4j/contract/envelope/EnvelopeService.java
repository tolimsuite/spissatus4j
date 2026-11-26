package cn.tolim.spissatus4j.contract.envelope;

import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import java.util.Map;

/**
 * Envelope creation, serialization, parsing and validation. Decoding is
 * fail-closed; unknown versions are rejected unless the version policy
 * explicitly supports them.
 */
public interface EnvelopeService {

    Envelope create(EncryptedData data, Map<String, String> attributes);

    byte[] encode(Envelope envelope, EnvelopeFormat format);

    Envelope decode(byte[] encoded);

    String encodeText(Envelope envelope, EnvelopeFormat format, BinaryEncoding encoding);

    Envelope decodeText(String text);

    void validate(Envelope envelope);

    boolean supportsVersion(int version);

    VersionPolicy versionPolicy();
}