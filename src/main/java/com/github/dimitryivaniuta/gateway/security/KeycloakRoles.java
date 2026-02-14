package com.github.dimitryivaniuta.gateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

/**
 * Helpers to map Keycloak role claims to Spring authorities.
 */
public final class KeycloakRoles {

    private KeycloakRoles() {}

    public static Collection<GrantedAuthority> extractRealmRoles(Jwt jwt) {
        Object realmAccess = jwt.getClaim("realm_access");
        if (!(realmAccess instanceof Map<?, ?> m)) {
            return List.of();
        }
        Object rolesObj = m.get("roles");
        if (!(rolesObj instanceof Collection<?> roles)) {
            return List.of();
        }
        List<GrantedAuthority> out = new ArrayList<>();
        for (Object r : roles) {
            if (r instanceof String role && !role.isBlank()) {
                out.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }
        return out;
    }
}
