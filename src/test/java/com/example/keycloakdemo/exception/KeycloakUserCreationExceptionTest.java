package com.example.keycloakdemo.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Clase de test unitario para {@link KeycloakUserCreationException}.
 * Verifica que la excepción personalizada se construye y se comporta correctamente,
 * incluyendo la propagación de mensajes y causas.
 */
class KeycloakUserCreationExceptionTest {

    @Test
    @DisplayName("Debería crear una excepción con un mensaje")
    void testConstructorWithMessage() {
        String errorMessage = "Error al crear usuario en Keycloak: Usuario ya existe.";
        KeycloakUserCreationException exception = new KeycloakUserCreationException(errorMessage);

        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        assertNull(exception.getCause(), "La causa de la excepción debe ser nula");
    }

    @Test
    @DisplayName("Debería crear una excepción con un mensaje y una causa raíz")
    void testConstructorWithMessageAndCause() {
        String errorMessage = "Error al establecer la contraseña.";
        Throwable cause = new RuntimeException("Conexión a Keycloak perdida.");
        KeycloakUserCreationException exception = new KeycloakUserCreationException(errorMessage, cause);

        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        assertEquals(cause, exception.getCause(), "La causa de la excepción debe ser la proporcionada");
        assertTrue(exception.getCause().getMessage().contains("Conexión a Keycloak perdida."), "El mensaje de la causa debe contener la cadena esperada");
    }

    @Test
    @DisplayName("Debería ser una instancia de RuntimeException")
    void testIsRuntimeException() {
        KeycloakUserCreationException exception = new KeycloakUserCreationException("Test");
        assertTrue(exception instanceof RuntimeException, "La excepción debe ser una instancia de RuntimeException");
    }
}
