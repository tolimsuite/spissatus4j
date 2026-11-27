package cn.tolim.spissatus4j.envelope.internal;

import cn.tolim.spissatus4j.contract.envelope.VersionPolicy;
import java.util.Objects;

/**
 * Envelope version policy supporting versions 1 and 2. Version 2 binds the
 * envelope metadata, including the resolved key version, through a header
 * hash; version 1 remains readable for compatibility. Migration hints are
 * non-sensitive guidance for callers that encounter old or unsupported
 * versions.
 */
public final class DefaultVersionPolicy implements VersionPolicy {

    public static final int CURRENT_VERSION = 2;

    private static final int LEGACY_VERSION = 1;

    public DefaultVersionPolicy() {
    }

    @Override
    public int currentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    public boolean isSupported(int version) {
        return version == LEGACY_VERSION || version == CURRENT_VERSION;
    }

    @Override
    public String migrationHint(int fromVersion) {
        if (fromVersion == CURRENT_VERSION) {
            return "Envelope version 2 is the current version; no migration is required.";
        }
        if (fromVersion == LEGACY_VERSION) {
            return "Envelope version 1 metadata is unauthenticated; re-encrypt with the unified API "
                    + "to produce a version 2 envelope.";
        }
        if (fromVersion < LEGACY_VERSION) {
            return "Envelope versions before 1 are not supported; recreate the envelope as version 2.";
        }
        return "Envelope version " + fromVersion
                + " is newer than the supported version 2; upgrade the library before decoding it.";
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