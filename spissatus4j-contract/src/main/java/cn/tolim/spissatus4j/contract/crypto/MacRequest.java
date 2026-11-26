package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Objects;

/** Request to compute a MAC with a managed MAC key. */
public record MacRequest(AlgorithmId algorithm, KeyId keyId, Long keyVersion, byte[] data,
                         CallerContext caller) {

    public MacRequest {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        data = Objects.requireNonNull(data, "data").clone();
        Objects.requireNonNull(caller, "caller");
    }

    @Override
    public byte[] data() {
        return data.clone();
    }
}