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
                        "spissatus.selection.profile=AUTO_AEAD_THEN_ETM",
                        "spissatus.selection.preferred-algorithms=AES-GCM,CHACHA20-POLY1305",
                        "spissatus.selection.allow-deprecated=true",
                        "spissatus.selection.allow-experimental=true",
                        "spissatus.selection.allow-family-reuse=true",
                        "spissatus.selection.allow-legacy-v1=true",
                        "spissatus.selection.max-candidates=8",
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
                    assertThat(properties.getSelection().getProfile())
                            .isEqualTo("AUTO_AEAD_THEN_ETM");
                    assertThat(properties.getSelection().getPreferredAlgorithms())
                            .containsExactly("AES-GCM", "CHACHA20-POLY1305");
                    assertThat(properties.getSelection().isAllowDeprecated()).isTrue();
                    assertThat(properties.getSelection().isAllowExperimental()).isTrue();
                    assertThat(properties.getSelection().isAllowFamilyReuse()).isTrue();
                    assertThat(properties.getSelection().isAllowLegacyV1()).isTrue();
                    assertThat(properties.getSelection().getMaxCandidates()).isEqualTo(8);
                    assertThat(settings.get("spissatus.selection.profile"))
                            .isEqualTo("AUTO_AEAD_THEN_ETM");
                    assertThat(settings.get("spissatus.selection.preferred-algorithms"))
                            .isEqualTo("AES-GCM,CHACHA20-POLY1305");
                    assertThat(settings.get("spissatus.selection.max-candidates")).isEqualTo("8");
                    assertThat(settings.toString()).contains("redacted").doesNotContain("secret-value");
                    assertThat(SpissatusSettings.complianceMode(properties))
                            .isEqualTo(ComplianceMode.GM_HYBRID);
                });
    }
}