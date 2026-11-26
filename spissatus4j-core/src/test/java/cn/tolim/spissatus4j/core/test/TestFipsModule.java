package cn.tolim.spissatus4j.core.test;

import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.core.testkit.TestAlgorithmProvider;
import java.util.Set;

/** Test-only FIPS-capable provider module used by facade provider-selection tests. */
public final class TestFipsModule implements SpissatusModule {

    @Override
    public String moduleId() {
        return "test-fips-module";
    }

    @Override
    public void contribute(ModuleContext context) {
        context.attribute("spissatus.fips.active", "true");
        context.registerAlgorithmProvider(new TestFipsProvider());
    }

    private static final class TestFipsProvider implements AlgorithmProvider {
        private final TestAlgorithmProvider delegate = new TestAlgorithmProvider();

        @Override
        public String providerId() {
            return "test-fips";
        }

        @Override
        public int priority() {
            return 200;
        }

        @Override
        public boolean fipsCapable() {
            return true;
        }

        @Override
        public Set<AlgorithmId> supportedAlgorithms() {
            return delegate.supportedAlgorithms();
        }

        @Override
        public AeadCipher aeadCipher(AlgorithmId algorithm) {
            return delegate.aeadCipher(algorithm);
        }

        @Override
        public AsymmetricCipher asymmetricCipher(AlgorithmId algorithm) {
            return delegate.asymmetricCipher(algorithm);
        }

        @Override
        public HashFunction hash(AlgorithmId algorithm) {
            return delegate.hash(algorithm);
        }

        @Override
        public MacFunction mac(AlgorithmId algorithm) {
            return delegate.mac(algorithm);
        }

        @Override
        public SignatureFunction signature(AlgorithmId algorithm) {
            return delegate.signature(algorithm);
        }

        @Override
        public KdfFunction kdf(AlgorithmId algorithm) {
            return delegate.kdf(algorithm);
        }

        @Override
        public SelfCheckReport selfCheck() {
            return delegate.selfCheck().withPrefix("test-fips");
        }
    }
}
