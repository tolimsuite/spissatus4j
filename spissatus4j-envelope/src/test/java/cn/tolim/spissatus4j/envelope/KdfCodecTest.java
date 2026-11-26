package cn.tolim.spissatus4j.envelope;

import static cn.tolim.spissatus4j.envelope.TestEnvelopes.bytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.envelope.internal.KdfCodec;
import java.util.List;
import org.junit.jupiter.api.Test;

class KdfCodecTest {

    @Test
    void canonicalArgon2idFormIsSortedAndRoundTrips() {
        KdfParameters.Argon2id parameters = TestEnvelopes.lowCostArgon2id();
        String canonical = KdfCodec.canonicalize(parameters);
        assertEquals("ARGON2ID;iterations=2;memoryKib=1024;outputBytes=32;parallelism=1;version=19",
                canonical);
        assertEquals(parameters.toMap(), KdfCodec.fromCanonical(canonical).toMap());
    }

    @Test
    void allKdfFamiliesRoundTripThroughCanonicalForm() {
        List<KdfParameters> all = List.of(
                TestEnvelopes.lowCostArgon2id(),
                new KdfParameters.Scrypt(1024, 8, 1, 32),
                new KdfParameters.Pbkdf2(1000, 32, "HmacSHA256"),
                new KdfParameters.Bcrypt(10),
                new KdfParameters.Hkdf(32, bytes(16, 42), "HmacSHA512"));
        for (KdfParameters parameters : all) {
            String canonical = KdfCodec.canonicalize(parameters);
            KdfParameters parsed = KdfCodec.fromCanonical(canonical);
            assertEquals(parameters.toMap(), parsed.toMap());
            assertEquals(parameters.algorithm(), parsed.algorithm());
        }
    }

    @Test
    void nonCanonicalOrderingIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "ARGON2ID;memoryKib=1024;iterations=2;outputBytes=32;parallelism=1;version=19"));
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "argon2id;iterations=2;memoryKib=1024;outputBytes=32;parallelism=1;version=19"));
    }

    @Test
    void unknownMissingAndDuplicateParametersAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "ARGON2ID;iterations=2;memoryKib=1024;outputBytes=32;parallelism=1;version=19;extra=1"));
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "ARGON2ID;iterations=2"));
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "MYSTERY-KDF;rounds=2"));
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "ARGON2ID;iterations=2;iterations=2;memoryKib=1024;outputBytes=32;parallelism=1;version=19"));
    }

    @Test
    void emptyHkdfInfoRoundTripsThroughCanonicalForm() {
        KdfParameters parameters = new KdfParameters.Hkdf(32, new byte[0], "HmacSHA256");
        String canonical = KdfCodec.canonicalize(parameters);
        assertEquals("HKDF;digest=HmacSHA256;info=;outputBytes=32", canonical);
        KdfParameters parsed = KdfCodec.fromCanonical(canonical);
        assertEquals(parameters.toMap(), parsed.toMap());
        assertEquals(parameters.algorithm(), parsed.algorithm());
    }

    @Test
    void invalidHkdfInfoIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> KdfCodec.fromCanonical(
                "HKDF;digest=HmacSHA256;info=%%%;outputBytes=32"));
    }
}