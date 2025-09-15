package com.example.keycloak.multitenant.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test unitario simple para {@link JwtProperties}.
 * Verifica que los getters y setters funcionen correctamente,
 * y que el valor por defecto de {@code expirationHours} sea 12.
 */
class JwtPropertiesTest {

    @Test
    void shouldSetAndGetSecretAndExpirationHours() {
        JwtProperties jwtProperties = new JwtProperties();

        assertEquals(12, jwtProperties.getExpirationHours(),
                "El valor por defecto de expirationHours debe ser 12");

        jwtProperties.setSecret("mi-secreto");
        jwtProperties.setExpirationHours(24);

        assertEquals("mi-secreto", jwtProperties.getSecret());
        assertEquals(24, jwtProperties.getExpirationHours());
    }
}
