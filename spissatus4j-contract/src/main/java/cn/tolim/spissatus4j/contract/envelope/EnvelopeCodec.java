package cn.tolim.spissatus4j.contract.envelope;

/**
 * Structural envelope codec (TLV or JSON). Parsers must be strict and
 * fail-closed: unknown fields, duplicate fields and length overflows are
 * rejected.
 */
public interface EnvelopeCodec {

    String formatId();

    byte[] encode(Envelope envelope);

    Envelope decode(byte[] encoded);

    boolean sniff(byte[] encoded);
}