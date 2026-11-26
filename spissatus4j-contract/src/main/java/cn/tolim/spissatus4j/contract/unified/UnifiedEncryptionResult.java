package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.envelope.Envelope;
import java.util.Objects;

/** Result of one unified encryption: a v2 envelope plus its selection report. */
public record UnifiedEncryptionResult(Envelope envelope, SelectionReport selection) {

    public UnifiedEncryptionResult {
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(selection, "selection");
    }
}