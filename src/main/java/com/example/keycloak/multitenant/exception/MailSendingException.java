package com.example.keycloak.multitenant.exception;

/**
 * Excepción personalizada para errores que ocurren durante el envío de correos electrónicos.
 * <p>
 * Esta es una excepción no comprobada (`RuntimeException`) que se utiliza para encapsular
 * y propagar errores relacionados con el servicio de correo, permitiendo que la aplicación
 * maneje la situación de forma centralizada sin requerir la declaración explícita de `throws`.
 *
 * @author Angel Fm
 * @version 1.0
 */
public class MailSendingException extends RuntimeException {

    /**
     * Constructor para crear una nueva instancia de {@code MailSendingException}
     * con un mensaje de error especifico.
     *
     * @param message El mensaje que describe la causa del error.
     */
    public MailSendingException(String message) {
        super(message);
    }

    /**
     * Constructor que crea una nueva instancia de la excepción con un mensaje detallado y
     * la causa original del error.
     *
     * @param message El mensaje descriptivo del error.
     * @param cause   La causa original del error, por lo general una excepción de nivel inferior.
     */
    public MailSendingException(String message, Throwable cause) {
        super(message, cause);
    }
}
