package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Versioned, self-describing KDF parameters. Parameters are persisted inside
 * envelopes so that keys can always be re-derived with the original cost.
 */
public sealed interface KdfParameters
        permits KdfParameters.Argon2id, KdfParameters.Scrypt, KdfParameters.Pbkdf2,
        KdfParameters.Bcrypt, KdfParameters.Hkdf {

    AlgorithmId algorithm();

    int outputBytes();

    Map<String, String> toMap();

    static Argon2id argon2idDefault() {
        return new Argon2id(65_536, 3, 1, 32, 19);
    }

    static Scrypt scryptDefault() {
        return new Scrypt(32_768, 8, 1, 32);
    }

    static Pbkdf2 pbkdf2Default() {
        return new Pbkdf2(600_000, 32, "HmacSHA256");
    }

    static Bcrypt bcryptDefault() {
        return new Bcrypt(12);
    }

    static Hkdf hkdfDefault(byte[] info) {
        return new Hkdf(32, info, "HmacSHA256");
    }

    /** RFC 9106 Argon2id parameters. */
    record Argon2id(int memoryKib, int iterations, int parallelism, int outputBytes, int version)
            implements KdfParameters {

        public Argon2id {
            if (memoryKib < 8 || memoryKib > 4_194_304) {
                throw new IllegalArgumentException("Invalid Argon2id memory cost");
            }
            if (iterations < 1 || iterations > 1000) {
                throw new IllegalArgumentException("Invalid Argon2id iteration count");
            }
            if (parallelism < 1 || parallelism > 255) {
                throw new IllegalArgumentException("Invalid Argon2id parallelism");
            }
            checkOutput(outputBytes);
            if (version != 16 && version != 19) {
                throw new IllegalArgumentException("Unsupported Argon2 version");
            }
        }

        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.ARGON2ID;
        }

        @Override
        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("algorithm", algorithm().id());
            map.put("memoryKib", Integer.toString(memoryKib));
            map.put("iterations", Integer.toString(iterations));
            map.put("parallelism", Integer.toString(parallelism));
            map.put("outputBytes", Integer.toString(outputBytes));
            map.put("version", Integer.toString(version));
            return Map.copyOf(map);
        }
    }

    /** RFC 7914 scrypt parameters. {@code n} must be a power of two. */
    record Scrypt(int n, int r, int p, int outputBytes) implements KdfParameters {

        public Scrypt {
            if (n < 2 || n > (1 << 20) || (n & (n - 1)) != 0) {
                throw new IllegalArgumentException("scrypt N must be a power of two between 2 and 2^20");
            }
            if (r < 1 || r > 32 || p < 1 || p > 16) {
                throw new IllegalArgumentException("Invalid scrypt r/p parameters");
            }
            checkOutput(outputBytes);
        }

        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.SCRYPT;
        }

        @Override
        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("algorithm", algorithm().id());
            map.put("n", Integer.toString(n));
            map.put("r", Integer.toString(r));
            map.put("p", Integer.toString(p));
            map.put("outputBytes", Integer.toString(outputBytes));
            return Map.copyOf(map);
        }
    }

    /** PBKDF2 parameters; PRF is a JCA HMAC name. */
    record Pbkdf2(int iterations, int outputBytes, String prf) implements KdfParameters {

        public Pbkdf2 {
            if (iterations < 1 || iterations > 10_000_000) {
                throw new IllegalArgumentException("Invalid PBKDF2 iteration count");
            }
            checkOutput(outputBytes);
            Objects.requireNonNull(prf, "prf");
            if (!prf.equals("HmacSHA256") && !prf.equals("HmacSHA512")) {
                throw new IllegalArgumentException("PBKDF2 PRF must be HmacSHA256 or HmacSHA512");
            }
        }

        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.PBKDF2;
        }

        @Override
        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("algorithm", algorithm().id());
            map.put("iterations", Integer.toString(iterations));
            map.put("outputBytes", Integer.toString(outputBytes));
            map.put("prf", prf);
            return Map.copyOf(map);
        }
    }

    /** Legacy bcrypt parameters. Raw bcrypt output is 24 bytes. */
    record Bcrypt(int cost) implements KdfParameters {

        public Bcrypt {
            if (cost < 4 || cost > 31) {
                throw new IllegalArgumentException("bcrypt cost must be between 4 and 31");
            }
        }

        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.BCRYPT;
        }

        @Override
        public int outputBytes() {
            return 24;
        }

        @Override
        public Map<String, String> toMap() {
            return Map.of("algorithm", algorithm().id(), "cost", Integer.toString(cost),
                    "outputBytes", "24");
        }
    }

    /** RFC 5869 HKDF parameters. */
    record Hkdf(int outputBytes, byte[] info, String digest) implements KdfParameters {

        public Hkdf {
            checkOutput(outputBytes);
            info = Objects.requireNonNull(info, "info").clone();
            if (info.length > 1024 * 1024) {
                throw new IllegalArgumentException("HKDF info must not exceed 1 MiB");
            }
            if (!"HmacSHA256".equals(digest) && !"HmacSHA512".equals(digest)) {
                throw new IllegalArgumentException("HKDF digest must be HmacSHA256 or HmacSHA512");
            }
        }

        @Override
        public byte[] info() {
            return info.clone();
        }

        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.HKDF;
        }

        @Override
        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("algorithm", algorithm().id());
            map.put("outputBytes", Integer.toString(outputBytes));
            map.put("digest", digest);
            map.put("info", Base64.getEncoder().encodeToString(info));
            return Map.copyOf(map);
        }

        @Override
        public String toString() {
            return "Hkdf[outputBytes=" + outputBytes + ", infoLength=" + info.length + ", digest=" + digest + "]";
        }
    }

    private static void checkOutput(int outputBytes) {
        if (outputBytes < 16 || outputBytes > 1024) {
            throw new IllegalArgumentException("Derived key length must be between 16 and 1024 bytes");
        }
    }
}