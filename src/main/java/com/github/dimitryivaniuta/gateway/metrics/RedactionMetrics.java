package com.github.dimitryivaniuta.gateway.metrics;

import com.github.dimitryivaniuta.gateway.logging.Redactor;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes redaction counters as Micrometer gauges.
 */
@Configuration
public class RedactionMetrics {

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> redactionMeters() {
        return registry -> {
            Gauge.builder("pii.redactions.email.total", Redactor::emailRedactions).register(registry);
            Gauge.builder("pii.redactions.phone.total", Redactor::phoneRedactions).register(registry);
            Gauge.builder("pii.redactions.card.total", Redactor::cardRedactions).register(registry);
        };
    }
}
