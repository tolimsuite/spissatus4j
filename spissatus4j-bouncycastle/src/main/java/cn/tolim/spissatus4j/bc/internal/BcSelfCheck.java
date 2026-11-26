package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.bc.interop.BcInteropVerifier;
import cn.tolim.spissatus4j.bc.interop.BcInteropVerifier.InteropReport;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.crypto.spec.SecretKeySpec;

/**
 * Known-answer and interoperability self-checks for the Bouncy Castle
 * provider. Failures are reported as {@link HealthStatus#DOWN} with
 * non-sensitive messages; a mismatch never propagates a secret.
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcSelfCheck {

    private static final byte[] SHA3_256_ABC = BcProviders.fromHex(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    private static final byte[] SHA256_ABC = BcProviders.fromHex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    private static final byte[] BLAKE2B_512_ABC = BcProviders.fromHex(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d"
                    + "17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    private static final byte[] AES_GCM_CIPHERTEXT = BcProviders.fromHex(
            "0388dace60b6a392f328c2b971b2fe78");
    private static final byte[] AES_GCM_TAG = BcProviders.fromHex(
            "ab6e47d42cec13bdf53a67b21257bddf");
    private static final byte[] CMAC_AES_KEY = BcProviders.fromHex(
            "2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] CMAC_AES_MESSAGE = BcProviders.fromHex(
            "6bc1bee22e409f96e93d7e117393172a");
    private static final byte[] CMAC_AES_TAG = BcProviders.fromHex(
            "070a16b46b4d4144f79bdd9dd04a287c");

    private BcSelfCheck() {
    }

    /** Runs all checks against the supplied provider and JCA implementation. */
    public static SelfCheckReport run(AlgorithmProvider provider, Provider jcaProvider) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(jcaProvider, "jcaProvider");
        Instant startedAt = Instant.now();
        List<SelfCheckResult> results = new ArrayList<>();

        if (provider.supports(AlgorithmId.SHA3_256)) {
            results.add(check("bc.hash.sha3-256", () -> knownDigest(provider, AlgorithmId.SHA3_256, SHA3_256_ABC)));
        }
        if (provider.supports(AlgorithmId.SHA_256)) {
            results.add(check("bc.hash.sha-256", () -> knownDigest(provider, AlgorithmId.SHA_256, SHA256_ABC)));
        }
        if (provider.supports(AlgorithmId.BLAKE2B_512)) {
            results.add(check("bc.hash.blake2b-512", () -> knownDigest(provider, AlgorithmId.BLAKE2B_512, BLAKE2B_512_ABC)));
        }
        if (provider.supports(AlgorithmId.AES_GCM)) {
            results.add(check("bc.aead.aes-gcm", () -> aesGcmKnownAnswer(provider)));
        }
        if (provider.supports(AlgorithmId.CMAC_AES)) {
            results.add(check("bc.mac.cmac-aes", () -> cmacKnownAnswer(provider)));
        }
        if (provider.supports(AlgorithmId.ECIES)) {
            results.add(check("bc.asymmetric.ecies", () -> eciesRoundTrip(provider, jcaProvider)));
        }
        if (provider.supports(AlgorithmId.RSA_PKCS1_SIGNATURE)) {
            results.add(check("bc.signature.rsa-pkcs1",
                    () -> rsaPkcs1Signature(provider, jcaProvider)));
        }
        if (provider.supports(AlgorithmId.ARGON2ID)) {
            results.add(check("bc.kdf.argon2id", () -> argon2idDeterministic(provider)));
        }
        if (provider.supports(AlgorithmId.SCRYPT)) {
            results.add(check("bc.kdf.scrypt", () -> scryptDeterministic(provider)));
        }

        try {
            BcInteropVerifier verifier = new BcInteropVerifier(jcaProvider);
            InteropReport aes = verifier.verifyAesGcmInterop();
            results.add(interopResult("bc.interop.aes-gcm", aes.aesGcm(), aes.failures()));
            InteropReport digests = verifier.verifyDigestInterop();
            results.add(interopResult("bc.interop.digest", digests.digest(), digests.failures()));
            InteropReport signatures = verifier.verifySignatureInterop();
            results.add(interopResult("bc.interop.signature", signatures.signature(),
                    signatures.failures()));
        } catch (RuntimeException e) {
            results.add(SelfCheckResult.down("bc.interop",
                    "Check failed: " + e.getClass().getSimpleName()));
        }

        return new SelfCheckReport(startedAt, Instant.now(), results);
    }

    private static void knownDigest(AlgorithmProvider provider, AlgorithmId algorithm, byte[] expected) {
        byte[] actual = provider.hash(algorithm).digest("abc".getBytes(StandardCharsets.US_ASCII));
        if (!MessageDigest.isEqual(actual, expected)) {
            throw new IllegalStateException("Known-answer mismatch");
        }
    }

    private static void aesGcmKnownAnswer(AlgorithmProvider provider) {
        byte[] keyBytes = new byte[16];
        byte[] nonceBytes = new byte[12];
        byte[] plaintext = new byte[16];
        AeadCipher cipher = provider.aeadCipher(AlgorithmId.AES_GCM);
        AeadResult result = cipher.encrypt(new SecretKeySpec(keyBytes, "AES"), plaintext,
                Nonce.of(nonceBytes), AAD.empty());
        if (!MessageDigest.isEqual(result.ciphertext(), AES_GCM_CIPHERTEXT)
                || !MessageDigest.isEqual(result.tag(), AES_GCM_TAG)) {
            throw new IllegalStateException("Known-answer mismatch");
        }
        byte[] decrypted = cipher.decrypt(new SecretKeySpec(keyBytes, "AES"), Nonce.of(nonceBytes),
                AES_GCM_CIPHERTEXT, AES_GCM_TAG, AAD.empty());
        if (!MessageDigest.isEqual(decrypted, plaintext)) {
            throw new IllegalStateException("Known-answer mismatch");
        }
    }

    private static void cmacKnownAnswer(AlgorithmProvider provider) {
        SecretKeySpec key = new SecretKeySpec(CMAC_AES_KEY.clone(), "AES");
        MacFunction mac = provider.mac(AlgorithmId.CMAC_AES);
        if (!mac.verify(key, CMAC_AES_MESSAGE, CMAC_AES_TAG)) {
            throw new IllegalStateException("Known-answer mismatch");
        }
    }

    private static void eciesRoundTrip(AlgorithmProvider provider, Provider jcaProvider) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", jcaProvider);
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generator.generateKeyPair();
            byte[] plaintext = "ecies self-check".getBytes(StandardCharsets.US_ASCII);
            AsymmetricCipher cipher = provider.asymmetricCipher(AlgorithmId.ECIES);
            byte[] sealed = cipher.encrypt(keyPair.getPublic(), plaintext);
            byte[] opened = cipher.decrypt(keyPair.getPrivate(), sealed);
            if (!MessageDigest.isEqual(plaintext, opened)) {
                throw new IllegalStateException("Known-answer mismatch");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ECIES self-check failed: "
                    + e.getClass().getSimpleName());
        }
    }

    private static void rsaPkcs1Signature(AlgorithmProvider provider, Provider jcaProvider) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", jcaProvider);
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            byte[] message = "rsa pkcs1 self-check".getBytes(StandardCharsets.US_ASCII);
            SignatureFunction signature = provider.signature(AlgorithmId.RSA_PKCS1_SIGNATURE);
            byte[] signed = signature.sign(keyPair.getPrivate(), message);
            if (!signature.verify(keyPair.getPublic(), message, signed)) {
                throw new IllegalStateException("Known-answer mismatch");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA PKCS#1 self-check failed: "
                    + e.getClass().getSimpleName());
        }
    }

    private static void argon2idDeterministic(AlgorithmProvider provider) {
        KdfParameters.Argon2id parameters = new KdfParameters.Argon2id(65_536, 2, 1, 32, 19);
        Salt salt = Salt.of("somesalt".getBytes(StandardCharsets.UTF_8));
        char[] password = "password".toCharArray();
        try {
            KdfFunction kdf = provider.kdf(AlgorithmId.ARGON2ID);
            byte[] first = kdf.derive(null, password, salt, parameters);
            byte[] second = kdf.derive(null, password, salt, parameters);
            if (first.length != 32 || !MessageDigest.isEqual(first, second)) {
                throw new IllegalStateException("Known-answer mismatch");
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void scryptDeterministic(AlgorithmProvider provider) {
        KdfParameters.Scrypt parameters = new KdfParameters.Scrypt(16, 1, 1, 32);
        Salt salt = Salt.of("selfcheck-salt".getBytes(StandardCharsets.UTF_8));
        char[] password = "password".toCharArray();
        try {
            KdfFunction kdf = provider.kdf(AlgorithmId.SCRYPT);
            byte[] first = kdf.derive(null, password, salt, parameters);
            byte[] second = kdf.derive(null, password, salt, parameters);
            if (first.length != 32 || !MessageDigest.isEqual(first, second)) {
                throw new IllegalStateException("Known-answer mismatch");
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static SelfCheckResult interopResult(String checkId, boolean passed, List<String> failures) {
        if (passed && failures.isEmpty()) {
            return SelfCheckResult.up(checkId, "Interoperability check passed");
        }
        String message = failures.isEmpty()
                ? "Interoperability check failed"
                : String.join("; ", failures);
        return SelfCheckResult.down(checkId, message);
    }

    private static SelfCheckResult check(String checkId, Check action) {
        long startedNanos = System.nanoTime();
        try {
            action.run();
            return new SelfCheckResult(checkId, HealthStatus.UP, "Known-answer check passed",
                    Duration.ofNanos(System.nanoTime() - startedNanos));
        } catch (RuntimeException e) {
            return new SelfCheckResult(checkId, HealthStatus.DOWN,
                    "Check failed: " + e.getClass().getSimpleName(),
                    Duration.ofNanos(System.nanoTime() - startedNanos));
        }
    }

    @FunctionalInterface
    private interface Check {
        void run();
    }
}