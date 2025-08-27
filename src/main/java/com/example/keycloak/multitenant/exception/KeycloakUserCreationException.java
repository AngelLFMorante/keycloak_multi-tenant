package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores que ocurran durante la creacion, actualizacion
 * o gestion de usuarios en el servidor de Keycloak.
 * <p>
 * Esta excepcion se lanza cuando una operacion relacionada con usuarios falla,
 * por ejemplo, si el nombre de usuario ya existe, si la peticion es invalida,
 * o si la comunicacion con la API de Keycloak presenta un problema.
 * <p>
 * Al ser una {@code RuntimeException}, no es necesario que los metodos la declaren
 * en su firma (clausula {@code throws}), lo que permite una gestion de errores
 * mas limpia y centralizada en la aplicacion.
 *
 * @author Angel Fm
 * @version 1.0
 */
public class KeycloakUserCreationException extends RuntimeException {

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakUserCreationException}
     * con un mensaje de error especifico.
     *
     * @param message El mensaje que describe la causa del error.
     */
    public KeycloakUserCreationException(String message) {
        super(message);
    }

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakUserCreationException}
     * con un mensaje de error y la excepcion subyacente que causo este error.
     * <p>
     * Este constructor es util para encapsular excepciones de bajo nivel de las APIs
     * de Keycloak, proporcionando un contexto mas amplio y especifico sobre el
     * problema original.
     *
     * @param message El mensaje que describe la causa del error.
     * @param cause   La excepcion que causo este error.
     */
    public KeycloakUserCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}