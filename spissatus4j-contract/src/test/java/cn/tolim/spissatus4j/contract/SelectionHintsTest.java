package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SelectionHintsTest {

    @Test
    void allowListsIntersectAndDenyListsUnion() {
        SelectionHints first = new SelectionHints("first", true,
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.CHACHA20_POLY1305), true,
                Set.of(AlgorithmId.AES_CBC), Map.of(AlgorithmId.AES_GCM, 256), true);
        SelectionHints second = new SelectionHints("second", true,
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.AES_CTR), true,
                Set.of(AlgorithmId.AES_CTR), Map.of(AlgorithmId.AES_GCM, 128), false);
        SelectionHints merged = SelectionHints.strictest(first, second);
        assertTrue(merged.allowListPresent());
        assertEquals(Set.of(AlgorithmId.AES_GCM), merged.allowedAlgorithms());
        assertEquals(Set.of(AlgorithmId.AES_CBC, AlgorithmId.AES_CTR), merged.deniedAlgorithms());
        assertEquals(256, merged.minimumKeyBits(AlgorithmId.AES_GCM));
        assertFalse(merged.allowExperimental());
        assertTrue(merged.permits(AlgorithmId.AES_GCM));
        assertFalse(merged.permits(AlgorithmId.AES_CTR));
        assertFalse(merged.permits(AlgorithmId.CHACHA20_POLY1305));
    }

    @Test
    void disjointAllowListsDenyEverything() {
        SelectionHints first = new SelectionHints("first", true,
                Set.of(AlgorithmId.AES_GCM), true, Set.of(), Map.of(), false);
        SelectionHints second = new SelectionHints("second", true,
                Set.of(AlgorithmId.CHACHA20_POLY1305), true, Set.of(), Map.of(), false);
        SelectionHints merged = SelectionHints.strictest(first, second);
        assertTrue(merged.allowListPresent());
        assertTrue(merged.allowedAlgorithms().isEmpty());
        assertFalse(merged.permits(AlgorithmId.AES_GCM));
        assertFalse(merged.permits(AlgorithmId.CHACHA20_POLY1305));
    }

    @Test
    void absentHintsDoNotNarrowSelection() {
        SelectionHints none = SelectionHints.none();
        assertFalse(none.available());
        assertTrue(none.permits(AlgorithmId.AES_GCM));
        assertEquals(0, none.minimumKeyBits(AlgorithmId.AES_GCM));
        assertFalse(none.allowExperimental());
    }
}