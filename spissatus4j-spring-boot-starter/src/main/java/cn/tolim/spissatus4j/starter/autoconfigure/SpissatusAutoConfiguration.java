package cn.tolim.spissatus4j.starter.autoconfigure;

import cn.tolim.spissatus4j.contract.api.Spissatus;
import cn.tolim.spissatus4j.contract.api.SpissatusBuilder;
import cn.tolim.spissatus4j.contract.runtime.SensitiveDataRedactor;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import cn.tolim.spissatus4j.core.runtime.DefaultSensitiveDataRedactor;
import cn.tolim.spissatus4j.starter.internal.SpissatusLogSanitizer;
import cn.tolim.spissatus4j.starter.internal.SpissatusSettings;
import cn.tolim.spissatus4j.starter.properties.SpissatusProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for the spissatus4j facade. Provider, key, envelope and
 * policy modules are discovered from the classpath and configured through
 * settings. A failed startup self-check aborts application startup by default.
 */
@AutoConfiguration
@ConditionalOnClass(Spissatus.class)
@ConditionalOnProperty(prefix = "spissatus", name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(SpissatusProperties.class)
public class SpissatusAutoConfiguration {

    @Bean(name = "spissatus", destroyMethod = "close")
    @ConditionalOnMissingBean(Spissatus.class)
    public Spissatus spissatus(SpissatusProperties properties) {
        SpissatusBuilder builder = SpissatusBuilders.builder()
                .discoverModules(true)
                .failClosed(properties.isFailClosed())
                .complianceMode(SpissatusSettings.complianceMode(properties))
                .selfCheckOnStartup(properties.getSelfCheck().isOnStartup())
                .selfCheckFailureFailsStartup(properties.getSelfCheck().isFailureFailsStartup());
        SpissatusSettings.settings(properties).forEach(builder::setting);
        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean(SensitiveDataRedactor.class)
    public SensitiveDataRedactor spissatusSensitiveDataRedactor() {
        return new DefaultSensitiveDataRedactor();
    }

    @Bean
    @ConditionalOnMissingBean(SpissatusLogSanitizer.class)
    public SpissatusLogSanitizer spissatusLogSanitizer(SensitiveDataRedactor redactor) {
        return new SpissatusLogSanitizer(redactor);
    }
}