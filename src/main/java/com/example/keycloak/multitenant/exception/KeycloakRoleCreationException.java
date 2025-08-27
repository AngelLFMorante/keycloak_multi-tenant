package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores relacionados con la creacion, actualizacion
 * o manipulacion de roles en el servidor de Keycloak.
 * <p>
 * Esta excepcion se lanza cuando una operacion de gestion de roles (como la creacion
 * de un nuevo rol o la asignacion de atributos) falla debido a un problema con
 * Keycloak, como un rol que ya existe o una respuesta inesperada de la API.
 * <p>
 * Al ser una {@code RuntimeException}, no es necesario que los metodos la declaren
 * en su firma (clausula {@code throws}), lo que permite una gestion de errores
 * mas limpia y centralizada.
 *
 * @author Angel Fm
 * @version 1.0
 */
public class KeycloakRoleCreationException extends RuntimeException {

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakRoleCreationException}
     * con un mensaje de error especifico.
     *
     * @param message El mensaje que describe la causa del error.
     */
    public KeycloakRoleCreationException(String message) {
        super(message);
    }

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakRoleCreationException}
     * con un mensaje de error y la excepcion que causo este error.
     * <p>
     * Este constructor es util para envolver excepciones de bajo nivel de las APIs
     * de Keycloak, proporcionando un contexto mas amplio y especifico sobre el
     * problema original.
     *
     * @param message El mensaje que describe la causa del error.
     * @param cause   La excepcion subyacente que provoco este error.
     */
    public KeycloakRoleCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}