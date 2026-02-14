package com.github.dimitryivaniuta.gateway;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Shared Postgres testcontainer for ITs.
 *
 * <p>Uses {@link DynamicPropertySource} so Spring picks up container JDBC settings during context bootstrap.</p>
 */
public abstract class TestcontainersConfig {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16")
            .withDatabaseName("app")
            .withUsername("app")
            .withPassword("app");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void postgresProps(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }
}
