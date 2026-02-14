package com.github.dimitryivaniuta.gateway.logging;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Redactor.
 */
class RedactorTest {

    @Test
    void redactsEmail() {
        String in = "email=john.doe+test@example.com";
        String out = Redactor.redact(in);
        assertThat(out).doesNotContain("john.doe+test@example.com");
        assertThat(out).contains("@example.com");
    }

    @Test
    void redactsPhone() {
        String in = "phone=+48 500 600 700";
        String out = Redactor.redact(in);
        assertThat(out).doesNotContain("+48 500 600 700");
        assertThat(out).contains("***PHONE***");
    }

    @Test
    void redactsCardWithLuhn() {
        String in = "card=4111 1111 1111 1111";
        String out = Redactor.redact(in);
        assertThat(out).doesNotContain("4111 1111 1111 1111");
        assertThat(out).contains("**** **** **** 1111");
    }

    @Test
    void doesNotRedactRandomNumberThatFailsLuhn() {
        String in = "id=1234 5678 9012 3456";
        String out = Redactor.redact(in);
        assertThat(out).contains("1234 5678 9012 3456");
    }
}
