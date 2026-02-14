package com.github.dimitryivaniuta.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Privacy-safe Logging Pipeline sample application.
 */
@SpringBootApplication
public class PrivacySafeLoggingPipelineApplication {

    /**
     * Starts the Spring Boot application.
     *
     * @param args CLI args
     */
    public static void main(String[] args) {
        SpringApplication.run(PrivacySafeLoggingPipelineApplication.class, args);
    }
}
