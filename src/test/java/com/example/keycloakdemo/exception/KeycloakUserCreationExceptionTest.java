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

        // Verificar que el mensaje de la excepción es el esperado
        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        // Verificar que no hay una causa raíz
        assertNull(exception.getCause(), "La causa de la excepción debe ser nula");
    }

    @Test
    @DisplayName("Debería crear una excepción con un mensaje y una causa raíz")
    void testConstructorWithMessageAndCause() {
        String errorMessage = "Error al establecer la contraseña.";
        Throwable cause = new RuntimeException("Conexión a Keycloak perdida.");
        KeycloakUserCreationException exception = new KeycloakUserCreationException(errorMessage, cause);

        // Verificar que el mensaje de la excepción es el esperado
        assertEquals(errorMessage, exception.getMessage(), "El mensaje de la excepción debe coincidir");
        // Verificar que la causa raíz es la esperada
        assertEquals(cause, exception.getCause(), "La causa de la excepción debe ser la proporcionada");
        // Verificar que el mensaje de la causa raíz es el esperado
        assertTrue(exception.getCause().getMessage().contains("Conexión a Keycloak perdida."), "El mensaje de la causa debe contener la cadena esperada");
    }

    @Test
    @DisplayName("Debería ser una instancia de RuntimeException")
    void testIsRuntimeException() {
        KeycloakUserCreationException exception = new KeycloakUserCreationException("Test");
        // Verificar que KeycloakUserCreationException es una subclase de RuntimeException
        assertTrue(exception instanceof RuntimeException, "La excepción debe ser una instancia de RuntimeException");
    }
}
