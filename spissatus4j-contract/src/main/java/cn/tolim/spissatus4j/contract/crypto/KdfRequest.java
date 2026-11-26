package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Objects;

/**
 * Request for password-based or input-key-material-based derivation.
 *
 * <p>HKDF consumes input key material; password KDFs consume a char[]
 * password. The two modes are mutually exclusive.</p>
 */
public final class KdfRequest {

    private final KdfParameters parameters;
    private final Salt salt;
    private final char[] password;
    private final byte[] inputKeyMaterial;
    private final CallerContext caller;

    private KdfRequest(Builder builder) {
        this.parameters = Objects.requireNonNull(builder.parameters, "parameters");
        this.salt = builder.salt == null ? Salt.empty() : builder.salt;
        this.caller = Objects.requireNonNull(builder.caller, "caller");
        boolean hkdf = parameters instanceof KdfParameters.Hkdf;
        if (hkdf) {
            if (builder.password != null) {
                throw new IllegalArgumentException("HKDF does not accept a password");
            }
            this.inputKeyMaterial = Objects.requireNonNull(builder.inputKeyMaterial,
                    "inputKeyMaterial is required for HKDF").clone();
            if (inputKeyMaterial.length == 0) {
                throw new IllegalArgumentException("HKDF input key material must not be empty");
            }
            this.password = null;
            if (salt.length() > 0 && salt.length() < 8) {
                throw new IllegalArgumentException("HKDF salt must be empty or at least 8 bytes");
            }
        } else {
            if (builder.inputKeyMaterial != null) {
                throw new IllegalArgumentException("Password KDFs do not accept input key material");
            }
            this.password = Objects.requireNonNull(builder.password,
                    "password is required for password KDFs").clone();
            if (password.length == 0) {
                throw new IllegalArgumentException("password must not be empty");
            }
            this.inputKeyMaterial = null;
            if (salt.length() < 8) {
                throw new IllegalArgumentException("Password KDF salt must be at least 8 bytes");
            }
        }
    }

    public static Builder builder(KdfParameters parameters, CallerContext caller) {
        return new Builder().parameters(parameters).caller(caller);
    }

    public KdfParameters parameters() {
        return parameters;
    }

    public Salt salt() {
        return salt;
    }

    public char[] password() {
        return password == null ? null : password.clone();
    }

    public byte[] inputKeyMaterial() {
        return inputKeyMaterial == null ? null : inputKeyMaterial.clone();
    }

    public CallerContext caller() {
        return caller;
    }

    @Override
    public String toString() {
        return "KdfRequest[algorithm=" + parameters.algorithm() + ", saltLength=" + salt.length() + "]";
    }

    public static final class Builder {
        private KdfParameters parameters;
        private Salt salt = Salt.empty();
        private char[] password;
        private byte[] inputKeyMaterial;
        private CallerContext caller;

        public Builder parameters(KdfParameters value) {
            this.parameters = value;
            return this;
        }

        public Builder salt(Salt value) {
            this.salt = value;
            return this;
        }

        public Builder password(char[] value) {
            this.password = value;
            return this;
        }

        public Builder inputKeyMaterial(byte[] value) {
            this.inputKeyMaterial = value;
            return this;
        }

        public Builder caller(CallerContext value) {
            this.caller = value;
            return this;
        }

        public KdfRequest build() {
            return new KdfRequest(this);
        }
    }
}