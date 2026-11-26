package cn.tolim.spissatus4j.starter.properties;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for spissatus4j.
 *
 * <p>Defaults are security-oriented: fail-closed, startup self-check, strict
 * policy, anonymous callers denied. Secrets (master password, HMAC key,
 * keystore password) should come from environment variables or a secret
 * manager, not from plain configuration files.</p>
 */
@ConfigurationProperties(prefix = "spissatus")
public class SpissatusProperties {

    private boolean enabled = true;
    private boolean failClosed = true;
    private String complianceMode = "STANDARD";

    private final Provider provider = new Provider();
    private final Keys keys = new Keys();
    private final Policy policy = new Policy();
    private final Envelope envelope = new Envelope();
    private final SelfCheck selfCheck = new SelfCheck();
    private final Nonce nonce = new Nonce();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isFailClosed() {
        return failClosed;
    }

    public void setFailClosed(boolean failClosed) {
        this.failClosed = failClosed;
    }

    public String getComplianceMode() {
        return complianceMode;
    }

    public void setComplianceMode(String complianceMode) {
        this.complianceMode = complianceMode;
    }

    public Provider getProvider() {
        return provider;
    }

    public Keys getKeys() {
        return keys;
    }

    public Policy getPolicy() {
        return policy;
    }

    public Envelope getEnvelope() {
        return envelope;
    }

    public SelfCheck getSelfCheck() {
        return selfCheck;
    }

    public Nonce getNonce() {
        return nonce;
    }

    public static class Provider {
        private boolean jca = true;
        private boolean bouncycastle = true;
        private boolean gm = true;
        private boolean fips;

        public boolean isJca() {
            return jca;
        }

        public void setJca(boolean jca) {
            this.jca = jca;
        }

        public boolean isBouncycastle() {
            return bouncycastle;
        }

        public void setBouncycastle(boolean bouncycastle) {
            this.bouncycastle = bouncycastle;
        }

        public boolean isGm() {
            return gm;
        }

        public void setGm(boolean gm) {
            this.gm = gm;
        }

        public boolean isFips() {
            return fips;
        }

        public void setFips(boolean fips) {
            this.fips = fips;
        }
    }

    public static class Keys {
        private String provider = "memory";
        private String fileDirectory;
        private String masterPassword;
        private String environmentPrefix = "SPISSATUS_KEY_";
        private String keystorePath;
        private String keystorePassword;
        private int retainVersions = 3;

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getFileDirectory() {
            return fileDirectory;
        }

        public void setFileDirectory(String fileDirectory) {
            this.fileDirectory = fileDirectory;
        }

        public String getMasterPassword() {
            return masterPassword;
        }

        public void setMasterPassword(String masterPassword) {
            this.masterPassword = masterPassword;
        }

        public String getEnvironmentPrefix() {
            return environmentPrefix;
        }

        public void setEnvironmentPrefix(String environmentPrefix) {
            this.environmentPrefix = environmentPrefix;
        }

        public String getKeystorePath() {
            return keystorePath;
        }

        public void setKeystorePath(String keystorePath) {
            this.keystorePath = keystorePath;
        }

        public String getKeystorePassword() {
            return keystorePassword;
        }

        public void setKeystorePassword(String keystorePassword) {
            this.keystorePassword = keystorePassword;
        }

        public int getRetainVersions() {
            return retainVersions;
        }

        public void setRetainVersions(int retainVersions) {
            this.retainVersions = retainVersions;
        }

        @Override
        public String toString() {
            return "Keys[provider=" + provider + ", fileDirectory=" + fileDirectory
                    + ", masterPassword=" + (masterPassword == null ? "unset" : "[REDACTED]")
                    + ", keystorePassword=" + (keystorePassword == null ? "unset" : "[REDACTED]") + "]";
        }
    }

    public static class Policy {
        private boolean allowAnonymous;
        private List<String> allowedCallers = new ArrayList<>();
        private List<String> allowedTenants = new ArrayList<>();
        private List<String> allowedEnvironments = new ArrayList<>();
        private String requiredRole;
        private List<String> denyAlgorithms = new ArrayList<>();
        private List<String> allowAlgorithms = new ArrayList<>();
        private List<String> crossTenantRoles = new ArrayList<>();
        private boolean allowExperimental;
        private int rateLimitPerMinute;
        private int tenantQuotaPerMinute;

        public boolean isAllowAnonymous() {
            return allowAnonymous;
        }

        public void setAllowAnonymous(boolean allowAnonymous) {
            this.allowAnonymous = allowAnonymous;
        }

        public List<String> getAllowedCallers() {
            return allowedCallers;
        }

        public void setAllowedCallers(List<String> allowedCallers) {
            this.allowedCallers = allowedCallers;
        }

        public List<String> getAllowedTenants() {
            return allowedTenants;
        }

        public void setAllowedTenants(List<String> allowedTenants) {
            this.allowedTenants = allowedTenants;
        }

        public List<String> getAllowedEnvironments() {
            return allowedEnvironments;
        }

        public void setAllowedEnvironments(List<String> allowedEnvironments) {
            this.allowedEnvironments = allowedEnvironments;
        }

        public String getRequiredRole() {
            return requiredRole;
        }

        public void setRequiredRole(String requiredRole) {
            this.requiredRole = requiredRole;
        }

        public List<String> getDenyAlgorithms() {
            return denyAlgorithms;
        }

        public void setDenyAlgorithms(List<String> denyAlgorithms) {
            this.denyAlgorithms = denyAlgorithms;
        }

        public List<String> getAllowAlgorithms() {
            return allowAlgorithms;
        }

        public void setAllowAlgorithms(List<String> allowAlgorithms) {
            this.allowAlgorithms = allowAlgorithms;
        }

        public List<String> getCrossTenantRoles() {
            return crossTenantRoles;
        }

        public void setCrossTenantRoles(List<String> crossTenantRoles) {
            this.crossTenantRoles = crossTenantRoles;
        }

        public boolean isAllowExperimental() {
            return allowExperimental;
        }

        public void setAllowExperimental(boolean allowExperimental) {
            this.allowExperimental = allowExperimental;
        }

        public int getRateLimitPerMinute() {
            return rateLimitPerMinute;
        }

        public void setRateLimitPerMinute(int rateLimitPerMinute) {
            this.rateLimitPerMinute = rateLimitPerMinute;
        }

        public int getTenantQuotaPerMinute() {
            return tenantQuotaPerMinute;
        }

        public void setTenantQuotaPerMinute(int tenantQuotaPerMinute) {
            this.tenantQuotaPerMinute = tenantQuotaPerMinute;
        }
    }

    public static class Envelope {
        private int maxBytes = 268_435_456;

        public int getMaxBytes() {
            return maxBytes;
        }

        public void setMaxBytes(int maxBytes) {
            this.maxBytes = maxBytes;
        }
    }

    public static class SelfCheck {
        private boolean onStartup = true;
        private boolean failureFailsStartup = true;

        public boolean isOnStartup() {
            return onStartup;
        }

        public void setOnStartup(boolean onStartup) {
            this.onStartup = onStartup;
        }

        public boolean isFailureFailsStartup() {
            return failureFailsStartup;
        }

        public void setFailureFailsStartup(boolean failureFailsStartup) {
            this.failureFailsStartup = failureFailsStartup;
        }
    }

    public static class Nonce {
        private int maxEntries = 1_000_000;
        private int ttlHours = 24;

        public int getMaxEntries() {
            return maxEntries;
        }

        public void setMaxEntries(int maxEntries) {
            this.maxEntries = maxEntries;
        }

        public int getTtlHours() {
            return ttlHours;
        }

        public void setTtlHours(int ttlHours) {
            this.ttlHours = ttlHours;
        }
    }

}
