package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Immutable parsed settings for the unified entry point. */
final class SelectionSettings {

    static final String PROFILE = "spissatus.selection.profile";
    static final String PREFERRED_ALGORITHMS = "spissatus.selection.preferred-algorithms";
    static final String ALLOW_DEPRECATED = "spissatus.selection.allow-deprecated";
    static final String ALLOW_EXPERIMENTAL = "spissatus.selection.allow-experimental";
    static final String ALLOW_FAMILY_REUSE = "spissatus.selection.allow-family-reuse";
    static final String ALLOW_LEGACY_V1 = "spissatus.selection.allow-legacy-v1";
    static final String MAX_CANDIDATES = "spissatus.selection.max-candidates";
    static final String ENVELOPE_MAX_BYTES = "spissatus.envelope.max-bytes";

    private final ComplianceMode mode;
    private final SelectionProfile defaultProfile;
    private final List<AlgorithmId> preferredAlgorithms;
    private final boolean allowDeprecated;
    private final boolean allowExperimental;
    private final boolean allowFamilyReuse;
    private final boolean allowLegacyV1;
    private final int maxCandidates;
    private final int envelopeMaxBytes;

    SelectionSettings(Map<String, String> settings, ComplianceMode mode) {
        Objects.requireNonNull(settings, "settings");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.defaultProfile = parseProfile(settings.get(PROFILE), mode);
        this.preferredAlgorithms = parseAlgorithms(settings.get(PREFERRED_ALGORITHMS));
        this.allowDeprecated = parseBoolean(settings, ALLOW_DEPRECATED, false);
        this.allowExperimental = parseBoolean(settings, ALLOW_EXPERIMENTAL, false);
        this.allowFamilyReuse = parseBoolean(settings, ALLOW_FAMILY_REUSE, false);
        this.allowLegacyV1 = parseBoolean(settings, ALLOW_LEGACY_V1, false);
        this.maxCandidates = parseInt(settings, MAX_CANDIDATES, 32, 1, 128);
        this.envelopeMaxBytes = parseInt(settings, ENVELOPE_MAX_BYTES,
                268_435_456, 1, Integer.MAX_VALUE);
    }

    SelectionProfile profileFor(UnifiedEncryptRequest request) {
        if (request.algorithm() != null || request.suite() != null || !request.candidates().isEmpty()) {
            return null;
        }
        SelectionProfile profile = request.profile() == null ? defaultProfile : request.profile();
        if (!profile.allowedIn(mode)) {
            throw new PolicyException(ErrorCode.COMPLIANCE_MODE_DENIED,
                    "Selection profile is not allowed by compliance mode " + mode);
        }
        return profile;
    }

    List<AlgorithmId> preferredOrder(SelectionProfile profile) {
        if (!preferredAlgorithms.isEmpty()) {
            return preferredAlgorithms;
        }
        return profile.defaultOrder(mode);
    }

    boolean allowDeprecated(UnifiedEncryptRequest request) {
        return allowDeprecated || request.allowDeprecated();
    }

    boolean allowExperimental(UnifiedEncryptRequest request) {
        return allowExperimental || request.allowExperimental();
    }

    boolean allowFamilyReuse(UnifiedEncryptRequest request) {
        return allowFamilyReuse || request.allowFamilyReuse();
    }

    boolean allowLegacyV1(boolean requested) {
        return allowLegacyV1 || requested;
    }

    int maxCandidates() {
        return maxCandidates;
    }

    int envelopeMaxBytes() {
        return envelopeMaxBytes;
    }

    private static SelectionProfile parseProfile(String value, ComplianceMode mode) {
        if (value == null || value.isBlank()) {
            return SelectionProfile.defaultFor(mode);
        }
        try {
            SelectionProfile profile = SelectionProfile.valueOf(
                    value.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
            if (!profile.allowedIn(mode)) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Selection profile is not allowed by compliance mode " + mode);
            }
            return profile;
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unsupported selection profile");
        }
    }

    private static List<AlgorithmId> parseAlgorithms(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<AlgorithmId> algorithms = new ArrayList<>();
        for (String part : value.split(",")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            AlgorithmId algorithm;
            try {
                algorithm = AlgorithmId.of(trimmed);
            } catch (IllegalArgumentException e) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Invalid algorithm in " + PREFERRED_ALGORITHMS);
            }
            if (!algorithm.isKnown()) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Unknown algorithm in " + PREFERRED_ALGORITHMS + ": " + algorithm.id());
            }
            AlgorithmFamily family = algorithm.family();
            if (family != AlgorithmFamily.AEAD && family != AlgorithmFamily.SYMMETRIC
                    && family != AlgorithmFamily.ASYMMETRIC) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Non-encryption algorithm in " + PREFERRED_ALGORITHMS + ": "
                                + algorithm.id());
            }
            algorithms.add(algorithm);
        }
        if (algorithms.isEmpty()) {
            return List.of();
        }
        return List.copyOf(algorithms);
    }

    private static boolean parseBoolean(Map<String, String> settings, String key,
                                        boolean defaultValue) {
        String value = settings.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        if ("true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                key + " must be true or false");
    }

    private static int parseInt(Map<String, String> settings, String key, int defaultValue,
                                int min, int max) {
        String value = settings.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < min || parsed > max) {
                throw new NumberFormatException("out of range");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    key + " must be an integer between " + min + " and " + max);
        }
    }
}