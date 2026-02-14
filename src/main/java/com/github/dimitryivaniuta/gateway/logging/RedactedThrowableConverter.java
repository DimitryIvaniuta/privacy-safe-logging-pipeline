package com.github.dimitryivaniuta.gateway.logging;

import ch.qos.logback.classic.pattern.ThrowableProxyConverter;
import ch.qos.logback.classic.spi.IThrowableProxy;

/**
 * Logback converter returning redacted exception string.
 */
public class RedactedThrowableConverter extends ThrowableProxyConverter {

    @Override
    protected String throwableProxyToString(IThrowableProxy tp) {
        return Redactor.redact(super.throwableProxyToString(tp));
    }
}
