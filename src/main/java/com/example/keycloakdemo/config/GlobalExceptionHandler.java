package com.example.keycloakdemo.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Clase global para el manejo de excepciones en la aplicacion REST
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Maneja las excepciones de tipo {@link WebClientResponseException}.
     * servicio externo a traves de WebClient (ej. 400, 401, 403, 404, 500)
     * @param ex La excepcion {@link WebClientResponseException} capturado.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error y el codigo de estado HTTP correspondiente
     */
    @ExceptionHandler(WebClientResponseException.class)
    public ResponseEntity<Map<String, Object>> handleWebClientResponseException(WebClientResponseException ex){
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", new Date());
        errorDetails.put("status", ex.getStatusCode().value());
        errorDetails.put("error", ex.getStatusText());
        errorDetails.put("message", "Error en la comunicacion con el servicio externo: "+ ex.getMessage());

        String path = (ex.getRequest() != null && ex.getRequest().getURI() != null) ? ex.getRequest().getURI().getPath() : "Desconocido";

        errorDetails.put("path", path);
        errorDetails.put("responseBody", ex.getResponseBodyAsString());

        System.err.println("WebClientResponseException capturado: "+ ex.getStatusCode() + " - " + ex.getResponseBodyAsString());

        return new ResponseEntity<>(errorDetails, ex.getStatusCode());
    }

    /**
     * Maneja las excepciones de tipo {@link IllegalArgumentException}
     * Argumentos de entrada no validas
     * @param ex la excepcion {@link IllegalArgumentException} capturada.
     * @return un {@link ResponseEntity} con un mapa JSon que describe el error
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(IllegalArgumentException ex){
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", new Date());
        errorDetails.put("status", HttpStatus.BAD_REQUEST.value());
        errorDetails.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
        errorDetails.put("message", ex.getMessage());

        System.err.println("IllegalArgumentException capturada: " + ex.getMessage());

        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja cualquier otra excecion no capturada por los manejadores especificos.
     * Proporciona un mensaje de error generico para evitar exponer detalles internos
     * @param ex La excepcion {@link Exception} generica capturada.
     * @return Un {@link ResponseEntity} describe el rror y codigo de estado Http 500
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAllUncaughtException(Exception ex){
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", new Date());
        errorDetails.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorDetails.put("error", HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
        errorDetails.put("message", "Ocurrió un error inesperado. Por favor, intente de nuevo mas tarde.");

        System.err.println("Excepcion no capturada: " + ex.getClass().getName() + " - " + ex.getMessage());
        ex.printStackTrace();

        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
