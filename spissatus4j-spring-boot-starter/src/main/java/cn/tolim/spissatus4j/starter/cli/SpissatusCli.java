package cn.tolim.spissatus4j.starter.cli;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.api.Spissatus;
import cn.tolim.spissatus4j.contract.api.SpissatusBuilder;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.crypto.SignRequest;
import cn.tolim.spissatus4j.contract.crypto.VerifyRequest;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.unified.AlgorithmCandidate;
import cn.tolim.spissatus4j.contract.unified.AlgorithmSuite;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Plain-Java command line interface. No secret material is printed; passwords
 * are preferably supplied through {@code SPISSATUS_MASTER_PASSWORD}.
 */
public final class SpissatusCli {

    private SpissatusCli() {
    }

    public static void main(String[] args) {
        int code = run(args, System.out, System.err);
        if (code != 0) {
            System.exit(code);
        }
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        if (args == null || args.length == 0 || "--help".equals(args[0]) || "help".equals(args[0])) {
            printUsage(out);
            return 0;
        }
        String command = args[0];
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            printUsage(err);
            return 2;
        }
        try {
            return switch (command) {
                case "self-check" -> selfCheck(options, out);
                case "capabilities" -> capabilities(options, out);
                case "generate-key" -> generateKey(options, out);
                case "encrypt" -> encrypt(options, out);
                case "decrypt" -> decrypt(options, out);
                case "sign" -> sign(options, out);
                case "verify" -> verify(options, out);
                case "inspect-envelope" -> inspectEnvelope(options, out);
                case "demo" -> demo(out);
                default -> {
                    err.println("error: unknown command " + command);
                    printUsage(err);
                    yield 2;
                }
            };
        } catch (SpissatusException e) {
            err.println("error [" + e.errorCode().name() + "]: " + e.getMessage());
            return 3;
        } catch (IOException e) {
            err.println("error: I/O failure: " + e.getMessage());
            return 4;
        } catch (Exception e) {
            err.println("error: operation failed");
            return 4;
        }
    }

    private static void printUsage(PrintStream out) {
        out.println("""
                spissatus4j CLI

                Usage: spissatus4j <command> [options]

                Commands:
                  self-check                     Build the facade and print self-check/capability summary
                  capabilities                   Print installed providers and algorithms
                  generate-key                   Generate a managed key
                  encrypt                        Encrypt a file into a self-describing envelope
                  decrypt                        Decrypt an envelope file
                  sign                           Sign a file with a managed private key
                  verify                         Verify a signature file
                  inspect-envelope               Print envelope metadata (no plaintext)
                  demo                           In-memory generate/encrypt/decrypt/sign/verify demonstration

                Common options:
                  --store-dir <path>             Enable the file key provider (persistent)
                  --master-password <secret>     File provider master password (prefer SPISSATUS_MASTER_PASSWORD)
                  --tenant <id>                  Caller tenant (default: default)
                  --compliance <mode>            STANDARD | FIPS | GM | GM_HYBRID

                generate-key: --id <keyId> --algorithm <id> [--type <AES|SM4|RSA|EC|ED25519|ED448|SM2|HMAC|SYMMETRIC>]
                              [--bits <n>]
                encrypt:      (--key <keyId> | --keys <id,id>) --in <file> [--out <file>] [--aad <text>]
                              [--algorithm <id> | --suite <id> | --profile <profile>]
                              [--allow-deprecated] [--allow-experimental] [--allow-family-reuse]
                              [--format JSON|TLV] [--encoding BASE64|BASE64URL|HEX|RAW]
                decrypt:      --in <file> [--out <file>] [--allow-legacy-v1]
                sign:         --key <keyId> --algorithm <id> --in <file> [--out <file>]
                verify:       --algorithm <id> --in <file> --signature <file> (--key <keyId> | --public-key <der/pem>)
                inspect:      --in <file>
                """);
    }

    // ------------------------------------------------------------------ commands

    private static int selfCheck(Options options, PrintStream out) {
        try (Spissatus facade = build(options)) {
            printSummary(facade, out);
        }
        return 0;
    }

    private static int capabilities(Options options, PrintStream out) {
        try (Spissatus facade = build(options)) {
            out.println("compliance=" + facade.capabilities().complianceMode()
                    + " algorithms=" + facade.capabilities().supportedAlgorithms().size()
                    + " fipsAvailable=" + facade.capabilities().fipsAvailable()
                    + " gmAvailable=" + facade.capabilities().gmAvailable());
            facade.capabilities().providers().forEach(provider -> out.println(
                    "provider " + provider.providerId() + " priority=" + provider.priority()
                            + " health=" + provider.health()
                            + " algorithms=" + provider.algorithms().size()));
            var selection = facade.selectionCapabilities();
            out.println("selectionProfiles=" + selection.profiles());
            selection.candidates().stream()
                    .filter(AlgorithmCandidate::available)
                    .limit(16)
                    .forEach(candidate -> out.println("candidate " + candidate.info().id()
                            + " rank=" + candidate.rank()));
        }
        return 0;
    }

    private static void printSummary(Spissatus facade, PrintStream out) {
        out.println("state=" + facade.state() + " health=" + facade.health()
                + " compliance=" + facade.capabilities().complianceMode()
                + " providers=" + facade.capabilities().providers().size()
                + " algorithms=" + facade.capabilities().supportedAlgorithms().size());
        var report = facade.selfCheckReport();
        out.println("selfCheck=" + report.overall() + " checks=" + report.checks().size());
        report.checks().forEach(check -> out.println(
                "  " + check.checkId() + " " + check.status() + " " + check.message()));
    }

    private static int generateKey(Options options, PrintStream out) {
        AlgorithmId algorithm = AlgorithmId.of(options.required("algorithm"));
        if (!algorithm.isKnown()) {
            throw new ConfigurationException(ErrorCode.ALGORITHM_UNKNOWN,
                    "Unknown algorithm: " + algorithm.id());
        }
        String keyIdValue = options.required("id");
        KeyType type = options.get("type") == null
                ? inferKeyType(algorithm) : parseKeyType(options.get("type"));
        Set<KeyUsage> usages = algorithm.info().usages();
        if (usages.isEmpty()) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Algorithm cannot be used for key generation: " + algorithm.id());
        }
        String tenant = options.get("tenant", "default");
        KeyGenerationRequest.Builder keyBuilder = KeyGenerationRequest.builder(type, algorithm, usages)
                .keyId(KeyId.of(keyIdValue)).tenantId(tenant);
        String bits = options.get("bits");
        if (bits != null) {
            keyBuilder.keyBits(parseBits(bits));
        }
        try (Spissatus facade = build(options)) {
            KeyDescriptor descriptor = facade.keyManager().generate(keyBuilder.build(),
                    caller(tenant));
            out.println("keyId=" + descriptor.keyId() + " version=" + descriptor.version()
                    + " type=" + descriptor.type() + " algorithm=" + descriptor.algorithm()
                    + " bits=" + descriptor.keyBits() + " state=" + descriptor.state()
                    + " tenant=" + descriptor.tenantId());
            if (options.get("store-dir") == null) {
                out.println("note: memory key provider is not persistent across CLI invocations");
            }
            return 0;
        }
    }

    private static int encrypt(Options options, PrintStream out) throws IOException {
        Path input = Path.of(options.required("in"));
        byte[] plaintext = Files.readAllBytes(input);
        String tenant = options.get("tenant", "default");
        EnvelopeFormat format = parseFormat(options.get("format", "JSON"));
        BinaryEncoding encoding = parseEncoding(options.get("encoding", "BASE64"));
        String singleKey = options.get("key");
        String keyList = options.get("keys");
        if ((singleKey == null) == (keyList == null)) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Exactly one of --key or --keys is required");
        }
        UnifiedEncryptRequest.Builder request = singleKey != null
                ? UnifiedEncryptRequest.builder(KeyId.of(singleKey), plaintext, caller(tenant))
                : UnifiedEncryptRequest.builder(parseKeyIds(keyList), plaintext, caller(tenant));
        String keyVersion = options.get("key-version");
        if (keyVersion != null) {
            request.keyVersion(Long.parseLong(keyVersion));
        }
        int explicitIntents = (options.get("algorithm") == null ? 0 : 1)
                + (options.get("suite") == null ? 0 : 1);
        if (explicitIntents > 1
                || (explicitIntents > 0 && options.get("profile") != null)) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Choose only one of --algorithm, --suite or --profile");
        }
        if (options.get("algorithm") != null) {
            request.algorithm(AlgorithmId.of(options.get("algorithm")));
        } else if (options.get("suite") != null) {
            request.suite(parseSuite(options.get("suite")));
        } else if (options.get("profile") != null) {
            request.profile(parseProfile(options.get("profile")));
        }
        request.aad(aad(options.get("aad")))
                .format(format)
                .encoding(encoding)
                .allowDeprecated(options.flag("allow-deprecated"))
                .allowExperimental(options.flag("allow-experimental"))
                .allowFamilyReuse(options.flag("allow-family-reuse"));
        try (Spissatus facade = build(options)) {
            UnifiedEncryptionResult result = facade.encrypt(request.build());
            Envelope envelope = result.envelope();
            Path output = Path.of(options.get("out", input + ".spissatus"));
            if (encoding == BinaryEncoding.RAW) {
                write(output, facade.envelopeService().encode(envelope, format));
            } else {
                write(output, facade.envelopeService().encodeText(envelope, format, encoding)
                        .getBytes(StandardCharsets.UTF_8));
            }
            out.println("encrypted=" + input + " -> " + output
                    + " algorithm=" + result.selection().selectedAlgorithm()
                    + " profile=" + result.selection().profileId()
                    + " envelopeVersion=" + envelope.version()
                    + " format=" + format + " encoding=" + encoding
                    + " ciphertextBytes=" + envelope.ciphertext().length);
            return 0;
        }
    }

    private static int decrypt(Options options, PrintStream out) throws IOException {
        Path input = Path.of(options.required("in"));
        byte[] bytes = Files.readAllBytes(input);
        String tenant = options.get("tenant", "default");
        boolean allowLegacy = options.flag("allow-legacy-v1");
        try (Spissatus facade = build(options)) {
            byte[] plaintext;
            try {
                plaintext = facade.decrypt(UnifiedDecryptRequest.builder(bytes, caller(tenant))
                        .allowLegacyV1(allowLegacy).build());
            } catch (EnvelopeException rawFailure) {
                if (rawFailure.errorCode() != ErrorCode.ENVELOPE_MALFORMED) {
                    throw rawFailure;
                }
                plaintext = facade.decrypt(UnifiedDecryptRequest.builder(
                                new String(bytes, StandardCharsets.UTF_8), caller(tenant))
                        .allowLegacyV1(allowLegacy).build());
            }
            Path output = Path.of(options.get("out", input + ".plain"));
            write(output, plaintext);
            out.println("decrypted=" + input + " -> " + output + " plaintextBytes=" + plaintext.length);
            return 0;
        }
    }

    private static int sign(Options options, PrintStream out) throws IOException {
        Path input = Path.of(options.required("in"));
        byte[] message = Files.readAllBytes(input);
        AlgorithmId algorithm = AlgorithmId.of(options.required("algorithm"));
        String tenant = options.get("tenant", "default");
        try (Spissatus facade = build(options)) {
            byte[] signature = facade.crypto().sign(SignRequest.builder(algorithm,
                            KeyId.of(options.required("key")), message, caller(tenant))
                    .build());
            Path output = Path.of(options.get("out", input + ".sig"));
            write(output, signature);
            out.println("signed=" + input + " -> " + output + " signatureBytes=" + signature.length);
            return 0;
        }
    }

    private static int verify(Options options, PrintStream out) throws Exception {
        Path input = Path.of(options.required("in"));
        byte[] message = Files.readAllBytes(input);
        byte[] signature = Files.readAllBytes(Path.of(options.required("signature")));
        AlgorithmId algorithm = AlgorithmId.of(options.required("algorithm"));
        String tenant = options.get("tenant", "default");
        try (Spissatus facade = build(options)) {
            VerifyRequest.Builder builder = VerifyRequest.builder(algorithm, message, signature,
                    caller(tenant));
            if (options.get("public-key") != null) {
                builder.publicKey(loadPublicKey(Path.of(options.get("public-key")), algorithm));
            } else {
                builder.keyId(KeyId.of(options.required("key")));
            }
            boolean valid = facade.crypto().verify(builder.build());
            out.println(valid ? "signature valid" : "signature invalid");
            return valid ? 0 : 5;
        }
    }

    private static int inspectEnvelope(Options options, PrintStream out) throws IOException {
        Path input = Path.of(options.required("in"));
        byte[] bytes = Files.readAllBytes(input);
        try (Spissatus facade = build(options)) {
            EnvelopeService service = facade.envelopeService();
            Envelope envelope;
            try {
                envelope = service.decode(bytes);
            } catch (EnvelopeException rawFailure) {
                envelope = service.decodeText(new String(bytes, StandardCharsets.UTF_8));
            }
            Map<String, String> details = new LinkedHashMap<>();
            details.put("version", Integer.toString(envelope.version()));
            details.put("headerHash", envelope.headerHash().length == 0 ? "absent" : "present");
            details.put("format", envelope.format().name());
            details.put("encoding", envelope.binaryEncoding().name());
            details.put("algorithm", envelope.algorithm().id());
            details.put("keyId", envelope.keyId().value());
            details.put("keyVersion", envelope.keyVersion().toString());
            details.put("nonceLength", Integer.toString(envelope.nonce().length()));
            details.put("ciphertextLength", Integer.toString(envelope.ciphertext().length));
            details.put("tagLength", Integer.toString(envelope.tag().length));
            details.put("aadLength", Integer.toString(envelope.aad().length()));
            details.put("createdAt", envelope.createdAt().toString());
            details.put("kdf", envelope.kdfParameters() == null
                    ? "none" : envelope.kdfParameters().algorithm().id());
            details.put("attributes", Integer.toString(envelope.attributes().size()));
            details.forEach((key, value) -> out.println(key + "=" + value));
            return 0;
        }
    }

    private static int demo(PrintStream out) {
        String tenant = "demo";
        CallerContext caller = caller(tenant);
        try (Spissatus facade = buildWithMemoryProvider()) {
            KeyDescriptor aes = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM, Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("demo-aes")).tenantId(tenant).build(), caller);
            byte[] plaintext = "spissatus4j demo plaintext".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult encrypted = facade.encrypt(UnifiedEncryptRequest.builder(
                            aes.keyId(), plaintext, caller).build());
            Envelope envelope = encrypted.envelope();
            byte[] decrypted = facade.decrypt(UnifiedDecryptRequest.builder(
                    facade.envelopeService().encode(envelope, envelope.format()), caller).build());
            if (!java.util.Arrays.equals(plaintext, decrypted)) {
                throw new IllegalStateException("roundtrip mismatch");
            }

            KeyDescriptor ed = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.ED25519, AlgorithmId.ED25519,
                            Set.of(KeyUsage.SIGN, KeyUsage.VERIFY))
                    .keyId(KeyId.of("demo-sign")).tenantId(tenant).build(), caller);
            byte[] signature = facade.crypto().sign(SignRequest.builder(AlgorithmId.ED25519,
                    ed.keyId(), plaintext, caller).build());
            boolean valid = facade.crypto().verify(VerifyRequest.builder(AlgorithmId.ED25519,
                            plaintext, signature, caller).keyId(ed.keyId()).build());
            if (!valid) {
                throw new IllegalStateException("signature verification failed");
            }
            out.println("DEMO OK state=" + facade.state() + " providers="
                    + facade.capabilities().providers().size()
                    + " envelopeVersion=" + envelope.version()
                    + " algorithm=" + encrypted.selection().selectedAlgorithm()
                    + " envelopeBytes=" + envelope.ciphertext().length
                    + " signatureBytes=" + signature.length);
            return 0;
        }
    }

    // ------------------------------------------------------------------ assembly

    private static Spissatus build(Options options) {
        SpissatusBuilder builder = SpissatusBuilders.builder()
                .discoverModules(true)
                .failClosed(true)
                .complianceMode(parseCompliance(options.get("compliance", "STANDARD")));
        builder.setting("spissatus.compliance.mode", options.get("compliance", "STANDARD"));
        String store = options.get("store-dir");
        if (store != null && !store.isBlank()) {
            String masterPassword = options.get("master-password");
            if (masterPassword == null || masterPassword.isBlank()) {
                masterPassword = System.getenv("SPISSATUS_MASTER_PASSWORD");
            }
            if (masterPassword == null || masterPassword.isBlank()) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "File key provider requires --master-password or SPISSATUS_MASTER_PASSWORD");
            }
            builder.setting("spissatus.key.provider", "file")
                    .setting("spissatus.key.file.directory", store)
                    .setting("spissatus.key.master.password", masterPassword);
        } else {
            builder.setting("spissatus.key.provider", "memory");
        }
        if (options.flag("allow-deprecated")) {
            builder.setting("spissatus.selection.allow-deprecated", "true");
        }
        if (options.flag("allow-experimental")) {
            builder.setting("spissatus.selection.allow-experimental", "true");
        }
        if (options.flag("allow-family-reuse")) {
            builder.setting("spissatus.selection.allow-family-reuse", "true");
        }
        if (options.flag("allow-legacy-v1")) {
            builder.setting("spissatus.selection.allow-legacy-v1", "true");
        }
        return builder.build();
    }

    private static Spissatus buildWithMemoryProvider() {
        return SpissatusBuilders.builder()
                .discoverModules(true)
                .failClosed(true)
                .setting("spissatus.key.provider", "memory")
                .build();
    }

    private static CallerContext caller(String tenant) {
        return CallerContext.of("cli", tenant, Set.of("crypto-user"));
    }

    private static KeyType parseKeyType(String value) {
        try {
            return KeyType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported key type: " + value);
        }
    }

    private static KeyType inferKeyType(AlgorithmId algorithm) {
        String id = algorithm.id();
        if (id.startsWith("AES")) {
            return KeyType.AES;
        }
        if (id.startsWith("SM4")) {
            return KeyType.SM4;
        }
        if (id.equals("CHACHA20-POLY1305")) {
            return KeyType.SYMMETRIC;
        }
        if (id.startsWith("HMAC")) {
            return KeyType.HMAC;
        }
        if (id.startsWith("RSA")) {
            return KeyType.RSA;
        }
        if (id.startsWith("ECDSA") || id.equals("ECIES")) {
            return KeyType.EC;
        }
        if (id.equals("ED25519")) {
            return KeyType.ED25519;
        }
        if (id.equals("ED448")) {
            return KeyType.ED448;
        }
        if (id.startsWith("SM2")) {
            return KeyType.SM2;
        }
        throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                "Cannot infer key type for " + algorithm.id() + "; pass --type");
    }

    private static EnvelopeFormat parseFormat(String value) {
        try {
            return EnvelopeFormat.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported envelope format: " + value);
        }
    }

    private static SelectionProfile parseProfile(String value) {
        try {
            return SelectionProfile.valueOf(value.trim().toUpperCase().replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported selection profile: " + value);
        }
    }

    private static AlgorithmSuite parseSuite(String value) {
        try {
            return AlgorithmSuite.of(value);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported algorithm suite: " + value);
        }
    }

    private static List<KeyId> parseKeyIds(String value) {
        List<KeyId> keyIds = new ArrayList<>();
        for (String part : value.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                keyIds.add(KeyId.of(trimmed));
            }
        }
        if (keyIds.isEmpty()) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "--keys must contain at least one key id");
        }
        return List.copyOf(keyIds);
    }

    private static int parseBits(String value) {
        try {
            int bits = Integer.parseInt(value.trim());
            if (bits < 1) {
                throw new NumberFormatException("non-positive");
            }
            return bits;
        } catch (NumberFormatException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "--bits must be a positive integer");
        }
    }

    private static BinaryEncoding parseEncoding(String value) {
        try {
            return BinaryEncoding.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported binary encoding: " + value);
        }
    }

    private static ComplianceMode parseCompliance(String value) {
        try {
            return ComplianceMode.valueOf(value.trim().toUpperCase().replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.INVALID_PARAMETER,
                    "Unsupported compliance mode: " + value);
        }
    }

    private static cn.tolim.spissatus4j.contract.crypto.AAD aad(String value) {
        return value == null ? cn.tolim.spissatus4j.contract.crypto.AAD.empty()
                : cn.tolim.spissatus4j.contract.crypto.AAD.ofUtf8(value);
    }

    private static PublicKey loadPublicKey(Path path, AlgorithmId algorithm) throws Exception {
        byte[] encoded = Files.readAllBytes(path);
        String text = new String(encoded, StandardCharsets.US_ASCII);
        if (text.contains("-----BEGIN")) {
            String body = text.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
            encoded = Base64.getDecoder().decode(body);
        }
        String jcaAlgorithm = switch (algorithm.id()) {
            case "ED25519" -> "Ed25519";
            case "ED448" -> "Ed448";
            case "ECDSA-P256", "ECDSA-P384", "SM2-SIGNATURE" -> "EC";
            default -> "RSA";
        };
        KeyFactory factory;
        if ("EC".equals(jcaAlgorithm) && Security.getProvider("BC") != null) {
            factory = KeyFactory.getInstance(jcaAlgorithm, "BC");
        } else {
            factory = KeyFactory.getInstance(jcaAlgorithm);
        }
        return factory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static void write(Path path, byte[] bytes) throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(path, bytes);
        try {
            Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions
                    .fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX file system.
        }
    }

    private static void write(Path path, String text) throws IOException {
        write(path, text.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------ options

    private static final class Options {
        private final Map<String, String> values = new LinkedHashMap<>();
        private final Set<String> flags = new java.util.HashSet<>();

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    throw new IllegalArgumentException("Unexpected argument: " + arg);
                }
                String name = arg.substring(2);
                String value = null;
                int equals = name.indexOf('=');
                if (equals >= 0) {
                    value = name.substring(equals + 1);
                    name = name.substring(0, equals);
                } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    value = args[++i];
                }
                if (name.isEmpty()) {
                    throw new IllegalArgumentException("Invalid option");
                }
                if (value == null) {
                    options.flags.add(name);
                } else {
                    options.values.put(name, value);
                }
            }
            return options;
        }

        String get(String name) {
            return values.get(name);
        }

        String get(String name, String defaultValue) {
            return values.getOrDefault(name, defaultValue);
        }

        boolean flag(String name) {
            return flags.contains(name);
        }

        String required(String name) {
            String value = values.get(name);
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("Missing required option --" + name);
            }
            return value;
        }
    }
}