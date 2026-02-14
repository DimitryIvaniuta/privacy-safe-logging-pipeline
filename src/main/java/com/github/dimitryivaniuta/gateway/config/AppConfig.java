package com.github.dimitryivaniuta.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Central configuration.
 */
@Configuration
@EnableConfigurationProperties({LoggingProperties.class, SecurityProperties.class, com.github.dimitryivaniuta.gateway.audit.crypto.AuditCryptoProperties.class})
public class AppConfig {
}
