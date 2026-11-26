package cn.tolim.spissatus4j.contract.envelope;

/** Envelope format version support and migration policy. */
public interface VersionPolicy {

    int currentVersion();

    boolean isSupported(int version);

    /** Non-sensitive migration guidance for an old but supported version. */
    String migrationHint(int fromVersion);
}