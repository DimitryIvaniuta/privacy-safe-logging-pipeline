package com.github.dimitryivaniuta.gateway.demo;

import jakarta.validation.constraints.NotBlank;

/**
 * Payload that includes PII-like fields for testing redaction.
 */
public record DemoPayload(
        @NotBlank String email,
        @NotBlank String phone,
        @NotBlank String cardNumber,
        @NotBlank String message
) {}
