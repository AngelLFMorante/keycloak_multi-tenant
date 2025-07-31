package com.example.keycloak.multitenant.exception;

public class KeycloakRoleCreationException extends RuntimeException {
    public KeycloakRoleCreationException(String message) {
        super(message);
    }

    public KeycloakRoleCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
