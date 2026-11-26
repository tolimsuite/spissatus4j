package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Objects;

/** Request to compute a digest. */
public record DigestRequest(AlgorithmId algorithm, byte[] data, CallerContext caller) {

    public DigestRequest {
        Objects.requireNonNull(algorithm, "algorithm");
        data = Objects.requireNonNull(data, "data").clone();
        Objects.requireNonNull(caller, "caller");
    }

    @Override
    public byte[] data() {
        return data.clone();
    }
}