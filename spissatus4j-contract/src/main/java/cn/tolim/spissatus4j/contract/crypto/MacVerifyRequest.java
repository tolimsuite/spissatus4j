package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Objects;

/** Request to verify a MAC in constant time. */
public record MacVerifyRequest(AlgorithmId algorithm, KeyId keyId, Long keyVersion, byte[] data,
                               byte[] expectedTag, CallerContext caller) {

    public MacVerifyRequest {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        data = Objects.requireNonNull(data, "data").clone();
        expectedTag = Objects.requireNonNull(expectedTag, "expectedTag").clone();
        Objects.requireNonNull(caller, "caller");
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    @Override
    public byte[] expectedTag() {
        return expectedTag.clone();
    }
}