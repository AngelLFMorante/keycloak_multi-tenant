package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores relacionados con la creacion o manipulacion de roles en Keycloak.
 * Se lanza cuando una operacion de rol falla, proporcionando un mensaje claro sobre la causa.
 */
public class KeycloakRoleCreationException extends RuntimeException {
    /**
     * Constructor que crea una nueva excepcion con un mensaje detallado.
     *
     * @param message El mensaje que describe la causa del error.
     */
    public KeycloakRoleCreationException(String message) {
        super(message);
    }

    /**
     * Constructor que crea una nueva excepcion con un mensaje y la causa raiz.
     *
     * @param message El mensaje que describe la causa del error.
     * @param cause   La excepcion que causo este error.
     */
    public KeycloakRoleCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
