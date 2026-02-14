package com.github.dimitryivaniuta.gateway.http;

import com.github.dimitryivaniuta.gateway.config.LoggingProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

/**
 * Adds/propagates correlation id for each request using MDC.
 */
@Component
public class CorrelationIdFilter extends OncePerRequestFilter {

    /** MDC key used by the logging pipeline. */
    public static final String MDC_KEY = "correlationId";

    private final LoggingProperties props;

    public CorrelationIdFilter(LoggingProperties props) {
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = Optional.ofNullable(props.correlationHeader()).orElse("X-Correlation-Id");
        String cid = Optional.ofNullable(request.getHeader(header))
                .filter(v -> !v.isBlank())
                .orElseGet(() -> UUID.randomUUID().toString());

        MDC.put(MDC_KEY, cid);
        response.setHeader(header, cid);

        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
