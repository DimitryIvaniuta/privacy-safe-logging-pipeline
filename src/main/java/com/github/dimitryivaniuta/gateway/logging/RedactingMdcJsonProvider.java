package com.github.dimitryivaniuta.gateway.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.fasterxml.jackson.core.JsonGenerator;
import net.logstash.logback.composite.loggingevent.MdcJsonProvider;

import java.io.IOException;
import java.util.Map;

/**
 * MDC JSON provider that redacts values before writing them to structured logs.
 *
 * <p>This is a safety-net: production code should avoid putting raw user input into MDC.
 * If it happens, this provider prevents accidental PII persistence.</p>
 */
public class RedactingMdcJsonProvider extends MdcJsonProvider {

    @Override
    public void writeTo(JsonGenerator generator, ILoggingEvent event) throws IOException {
        Map<String, String> mdc = event.getMDCPropertyMap();
        if (mdc == null || mdc.isEmpty()) {
            return;
        }

        String fieldName = getFieldName();
        generator.writeObjectFieldStart(fieldName);
        for (Map.Entry<String, String> e : mdc.entrySet()) {
            String key = e.getKey();
            String val = e.getValue();
            generator.writeStringField(key, Redactor.redact(val));
        }
        generator.writeEndObject();
    }
}
