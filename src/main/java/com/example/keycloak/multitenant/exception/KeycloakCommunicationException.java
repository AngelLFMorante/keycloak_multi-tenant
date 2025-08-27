package com.example.keycloak.multitenant.exception;

/**
 * Excepcion personalizada para errores de comunicacion con el servidor de Keycloak.
 * <p>
 * Esta excepcion se lanza cuando la aplicacion no puede conectarse o interactuar
 * correctamente con la API de Keycloak, ya sea por problemas de red, configuracion
 * incorrecta, o errores en la respuesta del servidor.
 * <p>
 * Al ser una {@code RuntimeException}, no es necesario que los metodos la declaren
 * en su firma (clausula {@code throws}), lo que simplifica la gestion de errores
 * en la capa de servicio y controlador.
 *
 * @author Angel Fm
 * @version 1.0
 */
public class KeycloakCommunicationException extends RuntimeException {

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakCommunicationException}
     * con un mensaje de error especifico.
     *
     * @param message El mensaje que describe la causa de la excepcion.
     */
    public KeycloakCommunicationException(String message) {
        super(message);
    }

    /**
     * Constructor para crear una nueva instancia de {@code KeycloakCommunicationException}
     * con un mensaje de error y una causa subyacente.
     * <p>
     * Este constructor es util cuando se necesita envolver una excepcion de nivel inferior
     * (como una {@code IOException} o {@code HttpStatusCodeException}) para proporcionar
     * mas contexto sobre el problema.
     *
     * @param message El mensaje que describe la excepcion.
     * @param cause   La causa original de la excepcion.
     */
    public KeycloakCommunicationException(String message, Throwable cause) {
        super(message, cause);
    }
}