package cn.tolim.spissatus4j.bc.interop;

import cn.tolim.spissatus4j.bc.internal.BcProviders;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies that Bouncy Castle interoperates with the JDK's own providers.
 *
 * <p>Individual verification methods populate only their own boolean in the
 * returned {@link InteropReport}; {@link #verifyAll()} runs all three and
 * aggregates the results. The verifier is side-effect free: it uses provider
 * instances directly and never modifies the global JCA registry.</p>
 */
public final class BcInteropVerifier {

    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;

    private final Provider bcProvider;
    private final Provider jceProvider;
    private final Provider ecProvider;
    private final Provider digestProvider;

    /** Creates a verifier using the registered (or a fresh) Bouncy Castle provider. */
    public BcInteropVerifier() {
        this(BcProviders.resolveProvider());
    }

    /** Creates a verifier using an explicit Bouncy Castle provider. */
    public BcInteropVerifier(Provider bcProvider) {
        this(bcProvider, Security.getProvider("SunJCE"), Security.getProvider("SunEC"),
                Security.getProvider("SUN"));
    }

    /** Creates a verifier with explicit providers; {@code null} marks an unavailable provider. */
    public BcInteropVerifier(Provider bcProvider, Provider jceProvider, Provider ecProvider,
                             Provider digestProvider) {
        this.bcProvider = Objects.requireNonNull(bcProvider, "bcProvider");
        this.jceProvider = jceProvider;
        this.ecProvider = ecProvider;
        this.digestProvider = digestProvider;
    }

    /** Verifies AES-GCM in both directions between SunJCE and Bouncy Castle. */
    public InteropReport verifyAesGcmInterop() {
        List<String> failures = new ArrayList<>();
        if (jceProvider == null) {
            failures.add("SunJCE provider is unavailable");
            return new InteropReport(false, false, false, failures);
        }
        try {
            SecretKey key = new SecretKeySpec(
                    BcProviders.fromHex("000102030405060708090a0b0c0d0e0f"), "AES");
            byte[] nonce = BcProviders.fromHex("0f0e0d0c0b0a090807060504");
            byte[] aad = "bc-interop-aad".getBytes(StandardCharsets.UTF_8);
            byte[] plaintext = "Bouncy Castle interoperability"
                    .getBytes(StandardCharsets.UTF_8);

            byte[] sunSealed = aeadEncrypt(jceProvider, key, nonce, aad, plaintext);
            byte[] openedByBc = aeadDecrypt(bcProvider, key, nonce, aad, sunSealed);
            if (!MessageDigest.isEqual(plaintext, openedByBc)) {
                failures.add("SunJCE to Bouncy Castle AES-GCM mismatch");
            }

            byte[] bcSealed = aeadEncrypt(bcProvider, key, nonce, aad, plaintext);
            byte[] openedBySun = aeadDecrypt(jceProvider, key, nonce, aad, bcSealed);
            if (!MessageDigest.isEqual(plaintext, openedBySun)) {
                failures.add("Bouncy Castle to SunJCE AES-GCM mismatch");
            }
            if (!MessageDigest.isEqual(sunSealed, bcSealed)) {
                failures.add("AES-GCM ciphertexts differ between providers");
            }
            return new InteropReport(failures.isEmpty(), false, false, failures);
        } catch (GeneralSecurityException e) {
            failures.add("AES-GCM interop failed: " + e.getClass().getSimpleName());
            return new InteropReport(false, false, false, failures);
        }
    }

    /** Verifies that SHA-256 and SHA3-256 agree between the JDK and Bouncy Castle. */
    public InteropReport verifyDigestInterop() {
        List<String> failures = new ArrayList<>();
        if (digestProvider == null) {
            failures.add("SUN provider is unavailable");
            return new InteropReport(false, false, false, failures);
        }
        byte[] data = "Bouncy Castle digest interoperability".getBytes(StandardCharsets.UTF_8);
        for (String algorithm : List.of("SHA-256", "SHA3-256")) {
            try {
                byte[] jcaDigest = MessageDigest.getInstance(algorithm, digestProvider).digest(data);
                byte[] bcDigest = MessageDigest.getInstance(algorithm, bcProvider).digest(data);
                if (!MessageDigest.isEqual(jcaDigest, bcDigest)) {
                    failures.add(algorithm + " digest mismatch between providers");
                }
            } catch (GeneralSecurityException e) {
                failures.add(algorithm + " digest interop failed: " + e.getClass().getSimpleName());
            }
        }
        return new InteropReport(false, failures.isEmpty(), false, failures);
    }

    /** Verifies ECDSA P-256 signatures across the JDK EC provider and Bouncy Castle. */
    public InteropReport verifySignatureInterop() {
        List<String> failures = new ArrayList<>();
        if (ecProvider == null) {
            failures.add("SunEC provider is unavailable");
            return new InteropReport(false, false, false, failures);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", ecProvider);
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generator.generateKeyPair();
            byte[] message = "Bouncy Castle signature interoperability"
                    .getBytes(StandardCharsets.UTF_8);

            byte[] jcaSignature = sign(ecProvider, keyPair.getPrivate(), message);
            if (!verify(bcProvider, keyPair.getPublic(), message, jcaSignature)) {
                failures.add("Bouncy Castle could not verify a SunEC ECDSA signature");
            }

            byte[] bcSignature = sign(bcProvider, keyPair.getPrivate(), message);
            if (!verify(ecProvider, keyPair.getPublic(), message, bcSignature)) {
                failures.add("SunEC could not verify a Bouncy Castle ECDSA signature");
            }
            return new InteropReport(false, false, failures.isEmpty(), failures);
        } catch (GeneralSecurityException e) {
            failures.add("ECDSA interop failed: " + e.getClass().getSimpleName());
            return new InteropReport(false, false, false, failures);
        }
    }

    /** Runs every interoperability check and aggregates the report. */
    public InteropReport verifyAll() {
        InteropReport aes = verifyAesGcmInterop();
        InteropReport digests = verifyDigestInterop();
        InteropReport signatures = verifySignatureInterop();
        List<String> failures = new ArrayList<>(aes.failures());
        failures.addAll(digests.failures());
        failures.addAll(signatures.failures());
        return new InteropReport(aes.aesGcm(), digests.digest(), signatures.signature(), failures);
    }

    private static byte[] aeadEncrypt(Provider provider, SecretKey key, byte[] nonce, byte[] aad,
                                      byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] aeadDecrypt(Provider provider, SecretKey key, byte[] nonce, byte[] aad,
                                      byte[] sealed) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, provider);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(sealed);
    }

    private static byte[] sign(Provider provider, PrivateKey key, byte[] message)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA", provider);
        signature.initSign(key);
        signature.update(message);
        return signature.sign();
    }

    private static boolean verify(Provider provider, PublicKey key, byte[] message, byte[] signature)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("SHA256withECDSA", provider);
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    /**
     * Result of an interoperability verification.
     *
     * @param aesGcm whether the AES-GCM check passed
     * @param digest whether the digest check passed
     * @param signature whether the signature check passed
     * @param failures non-sensitive failure descriptions
     */
    public record InteropReport(boolean aesGcm, boolean digest, boolean signature,
                                List<String> failures) {

        public InteropReport {
            failures = List.copyOf(Objects.requireNonNull(failures, "failures"));
        }

        /** True when all three checks passed and no failure was recorded. */
        public boolean passed() {
            return aesGcm && digest && signature && failures.isEmpty();
        }
    }
}