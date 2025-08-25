package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores que ocurran durante la creacion o gestion de usuarios en Keycloak.
 * Se lanza cuando una operacion de usuario falla, como un fallo en la creacion, actualizacion o eliminacion.
 */
public class KeycloakUserCreationException extends RuntimeException {
    /**
     * Constructor que crea una nueva excepcion con un mensaje detallado.
     *
     * @param message El mensaje que describe la causa del error.
     */
    public KeycloakUserCreationException(String message) {
        super(message);
    }

    /**
     * Constructor que crea una nueva excepcion con un mensaje y la causa raiz.
     *
     * @param message El mensaje que describe la causa del error.
     * @param cause   La excepcion que causo este error.
     */
    public KeycloakUserCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
