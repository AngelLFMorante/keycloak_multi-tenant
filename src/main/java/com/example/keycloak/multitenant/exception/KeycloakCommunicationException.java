package com.example.keycloak.multitenant.exception;

public class KeycloakCommunicationException extends RuntimeException {
    public KeycloakCommunicationException(String message) {
        super(message);
    }

    public KeycloakCommunicationException(String message, Throwable cause) {
        super(message, cause);
    }
}
