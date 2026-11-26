package cn.tolim.spissatus4j.envelope.internal;

import cn.tolim.spissatus4j.contract.envelope.VersionPolicy;
import java.util.Objects;

/**
 * Envelope version policy supporting exactly version 1. Migration hints are
 * non-sensitive guidance for callers that encounter unsupported versions.
 */
public final class DefaultVersionPolicy implements VersionPolicy {

    public static final int CURRENT_VERSION = 1;

    public DefaultVersionPolicy() {
    }

    @Override
    public int currentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    public boolean isSupported(int version) {
        return version == CURRENT_VERSION;
    }

    @Override
    public String migrationHint(int fromVersion) {
        if (fromVersion == CURRENT_VERSION) {
            return "Envelope version 1 is the current version; no migration is required.";
        }
        if (fromVersion < CURRENT_VERSION) {
            return "Envelope versions before 1 are not supported; recreate the envelope as version 1.";
        }
        return "Envelope version " + fromVersion
                + " is newer than the supported version 1; upgrade the library before decoding it.";
    }

    @Override
    public String toString() {
        return "DefaultVersionPolicy[current=" + CURRENT_VERSION + "]";
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DefaultVersionPolicy;
    }

    @Override
    public int hashCode() {
        return Objects.hash(CURRENT_VERSION);
    }
}