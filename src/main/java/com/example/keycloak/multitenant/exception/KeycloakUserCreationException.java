package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores que ocurran durante la creacion o gestion de usuarios en Keycloak
 */
public class KeycloakUserCreationException extends RuntimeException {
    public KeycloakUserCreationException(String message) {
        super(message);
    }

    public KeycloakUserCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
