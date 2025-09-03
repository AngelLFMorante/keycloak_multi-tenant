package com.example.keycloak.multitenant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class KeycloakMultitenantApplicationMainTest {

    @Test
    @DisplayName("Debe iniciar la aplicación sin lanzar excepciones")
    void main_shouldStartApplicationWithoutErrors() {
        assertDoesNotThrow(() -> KeycloakMultitenantApplication.main(new String[]{}));
    }
}
