package com.example.keycloak.multitenant.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Clase de test unitario para {@link KeycloakCommunicationException}.
 * Verifica que la excepción personalizada se construye y se comporta correctamente,
 * incluyendo la propagación de mensajes y causas.
 */
class KeycloakCommunicationExceptionTest {

    @Test
    @DisplayName("Debería crear una excepción con un mensaje")
    void testConstructorWithMessage() {
        String errorMessage = "Error al crear usuario en Keycloak: Usuario ya existe.";
        KeycloakCommunicationException exception = new KeycloakCommunicationException(errorMessage);

        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        assertNull(exception.getCause(), "La causa de la excepción debe ser nula");
    }

    @Test
    @DisplayName("Debería crear una excepción con un mensaje y una causa raíz")
    void testConstructorWithMessageAndCause() {
        String errorMessage = "Error al establecer la contraseña.";
        Throwable cause = new RuntimeException("Conexión a Keycloak perdida.");
        KeycloakCommunicationException exception = new KeycloakCommunicationException(errorMessage, cause);

        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        assertEquals(cause, exception.getCause(), "La causa de la excepción debe ser la proporcionada");
        assertTrue(exception.getCause().getMessage().contains("Conexión a Keycloak perdida."), "El mensaje de la causa debe contener la cadena esperada");
    }

    @Test
    @DisplayName("Debería ser una instancia de RuntimeException")
    void testIsRuntimeException() {
        KeycloakCommunicationException exception = new KeycloakCommunicationException("Test");
        assertTrue(exception instanceof RuntimeException, "La excepción debe ser una instancia de RuntimeException");
    }
}