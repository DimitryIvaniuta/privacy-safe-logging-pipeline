package com.github.dimitryivaniuta.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Demo security configuration properties.
 */
@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(List<User> users) {

    public record User(String username, String password, List<String> roles) {}
}
