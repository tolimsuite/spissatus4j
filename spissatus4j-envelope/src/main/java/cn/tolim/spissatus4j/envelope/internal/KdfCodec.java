package cn.tolim.spissatus4j.envelope.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Converts {@link KdfParameters} to and from their canonical envelope
 * representation. The canonical text form is
 * {@code ALGORITHM;key=value;key=value...} with keys sorted ascending. Empty
 * values are valid and preserved (HKDF permits empty {@code info}), so the
 * canonicalizer and parser stay symmetric.
 */
public final class KdfCodec {

    private KdfCodec() {
    }

    /** Canonical, deterministic text form used by the TLV codec and size checks. */
    public static String canonicalize(KdfParameters parameters) {
        Objects.requireNonNull(parameters, "parameters");
        Map<String, String> encoded = parameters.toMap();
        String algorithm = encoded.get("algorithm");
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("Missing KDF algorithm");
        }
        TreeMap<String, String> sorted = new TreeMap<>(encoded);
        sorted.remove("algorithm");
        StringBuilder result = new StringBuilder(algorithm);
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || value == null || key.isEmpty()
                    || key.indexOf(';') >= 0 || key.indexOf('=') >= 0
                    || value.indexOf(';') >= 0) {
                throw new IllegalArgumentException("Invalid KDF parameter");
            }
            result.append(';').append(key).append('=').append(value);
        }
        return result.toString();
    }

    /** Parses the canonical text form and rejects non-canonical orderings. */
    public static KdfParameters fromCanonical(String canonical) {
        if (canonical == null || canonical.isEmpty()) {
            throw new IllegalArgumentException("Missing canonical KDF parameters");
        }
        String[] parts = canonical.split(";", -1);
        if (parts.length == 0 || parts[0].isEmpty()) {
            throw new IllegalArgumentException("Invalid canonical KDF parameters");
        }
        Map<String, String> parameters = new HashMap<>();
        parameters.put("algorithm", parts[0]);
        for (int index = 1; index < parts.length; index++) {
            String part = parts[index];
            if (part.isEmpty()) {
                throw new IllegalArgumentException("Invalid canonical KDF parameters");
            }
            int separator = part.indexOf('=');
            if (separator <= 0) {
                throw new IllegalArgumentException("Invalid canonical KDF parameter");
            }
            String key = part.substring(0, separator);
            String value = part.substring(separator + 1);
            if (parameters.putIfAbsent(key, value) != null) {
                throw new IllegalArgumentException("Duplicate KDF parameter");
            }
        }
        KdfParameters parsed = fromMap(parameters);
        if (!canonicalize(parsed).equals(canonical)) {
            throw new IllegalArgumentException("KDF parameters are not canonical");
        }
        return parsed;
    }

    /**
     * Builds typed KDF parameters from a flattened string map containing an
     * {@code algorithm} entry. Unknown or missing entries are rejected.
     */
    public static KdfParameters fromMap(Map<String, String> raw) {
        Objects.requireNonNull(raw, "raw");
        String algorithmText = raw.get("algorithm");
        if (algorithmText == null || algorithmText.isBlank()) {
            throw new IllegalArgumentException("Missing KDF algorithm");
        }
        AlgorithmId algorithm;
        try {
            algorithm = AlgorithmId.of(algorithmText);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid KDF algorithm identifier");
        }
        if (!algorithm.isKnown()) {
            throw new IllegalArgumentException("Unknown KDF algorithm");
        }
        Map<String, String> parameters = new HashMap<>(raw);
        parameters.remove("algorithm");

        if (algorithm.equals(AlgorithmId.ARGON2ID)) {
            requireKeys(parameters, "iterations", "memoryKib", "outputBytes", "parallelism", "version");
            return new KdfParameters.Argon2id(
                    intParameter(parameters, "memoryKib"),
                    intParameter(parameters, "iterations"),
                    intParameter(parameters, "parallelism"),
                    intParameter(parameters, "outputBytes"),
                    intParameter(parameters, "version"));
        }
        if (algorithm.equals(AlgorithmId.SCRYPT)) {
            requireKeys(parameters, "n", "outputBytes", "p", "r");
            return new KdfParameters.Scrypt(
                    intParameter(parameters, "n"),
                    intParameter(parameters, "r"),
                    intParameter(parameters, "p"),
                    intParameter(parameters, "outputBytes"));
        }
        if (algorithm.equals(AlgorithmId.PBKDF2)) {
            requireKeys(parameters, "iterations", "outputBytes", "prf");
            return new KdfParameters.Pbkdf2(
                    intParameter(parameters, "iterations"),
                    intParameter(parameters, "outputBytes"),
                    stringParameter(parameters, "prf"));
        }
        if (algorithm.equals(AlgorithmId.BCRYPT)) {
            requireKeys(parameters, "cost", "outputBytes");
            if (intParameter(parameters, "outputBytes") != 24) {
                throw new IllegalArgumentException("Invalid bcrypt output length");
            }
            return new KdfParameters.Bcrypt(intParameter(parameters, "cost"));
        }
        if (algorithm.equals(AlgorithmId.HKDF)) {
            requireKeys(parameters, "digest", "info", "outputBytes");
            byte[] info;
            try {
                info = Base64.getDecoder().decode(stringParameter(parameters, "info"));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid HKDF info encoding");
            }
            return new KdfParameters.Hkdf(
                    intParameter(parameters, "outputBytes"),
                    info,
                    stringParameter(parameters, "digest"));
        }
        throw new IllegalArgumentException("KDF algorithm is not representable in an envelope");
    }

    private static void requireKeys(Map<String, String> parameters, String... keys) {
        Set<String> expected = Set.of(keys);
        if (!parameters.keySet().equals(expected)) {
            throw new IllegalArgumentException("Invalid KDF parameter set");
        }
        for (String key : keys) {
            if (parameters.get(key) == null) {
                throw new IllegalArgumentException("Missing KDF parameter");
            }
        }
    }

    private static int intParameter(Map<String, String> parameters, String key) {
        String value = parameters.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing KDF parameter");
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid KDF parameter");
        }
    }

    private static String stringParameter(Map<String, String> parameters, String key) {
        String value = parameters.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing KDF parameter");
        }
        return value;
    }
}