package com.github.dimitryivaniuta.gateway.logging;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * Logback converter returning redacted formatted message.
 */
public class RedactedMessageConverter extends ClassicConverter {

    @Override
    public String convert(ILoggingEvent event) {
        return event == null ? "" : Redactor.redact(event.getFormattedMessage());
    }
}
