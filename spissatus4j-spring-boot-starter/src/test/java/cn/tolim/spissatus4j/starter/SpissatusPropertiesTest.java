package cn.tolim.spissatus4j.starter;

import static org.assertj.core.api.Assertions.assertThat;

import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.starter.internal.SpissatusSettings;
import cn.tolim.spissatus4j.starter.properties.SpissatusProperties;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class SpissatusPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(SpissatusProperties.class)
    static class TestConfig {
    }

    @Test
    void bindsSecurityRelevantProperties() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "spissatus.fail-closed=false",
                        "spissatus.compliance-mode=GM_HYBRID",
                        "spissatus.provider.bouncycastle=false",
                        "spissatus.keys.provider=file",
                        "spissatus.keys.file-directory=/tmp/keys",
                        "spissatus.keys.master-password=secret-value",
                        "spissatus.policy.allow-anonymous=true",
                        "spissatus.policy.allowed-callers=one,two",
                        "spissatus.policy.rate-limit-per-minute=5",
                        "spissatus.self-check.failure-fails-startup=false")
                .run(context -> {
                    SpissatusProperties properties = context.getBean(SpissatusProperties.class);
                    assertThat(properties.isFailClosed()).isFalse();
                    assertThat(properties.getComplianceMode()).isEqualTo("GM_HYBRID");
                    assertThat(properties.getProvider().isBouncycastle()).isFalse();
                    assertThat(properties.getKeys().getProvider()).isEqualTo("file");
                    assertThat(properties.getKeys().toString()).doesNotContain("secret-value");
                    assertThat(properties.getPolicy().getAllowedCallers()).containsExactly("one", "two");
                    Map<String, String> settings = SpissatusSettings.settings(properties);
                    assertThat(settings.get("spissatus.policy.allowed-callers")).isEqualTo("one,two");
                    assertThat(settings.get("spissatus.key.master.password")).isEqualTo("secret-value");
                    assertThat(settings.toString()).contains("redacted").doesNotContain("secret-value");
                    assertThat(SpissatusSettings.complianceMode(properties))
                            .isEqualTo(ComplianceMode.GM_HYBRID);
                });
    }
}