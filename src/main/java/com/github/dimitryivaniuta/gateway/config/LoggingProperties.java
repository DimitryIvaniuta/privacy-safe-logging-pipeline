package com.github.dimitryivaniuta.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Logging properties.
 *
 * @param correlationHeader header that carries correlation id
 */
@ConfigurationProperties(prefix = "app.logging")
public record LoggingProperties(String correlationHeader) {
}
