package com.example.keycloak.multitenant.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test unitario simple para {@link AppProperties}.
 * Verifica que los getters y setters funcionen correctamente.
 */
class AppPropertiesTest {

    @Test
    void shouldSetAndGetBaseUrl() {
        AppProperties props = new AppProperties();

        props.setBaseUrl("http://localhost:8081");

        assertEquals("http://localhost:8081", props.getBaseUrl());
    }
}
