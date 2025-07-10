package com.example.keycloakdemo.config;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Clase global para el manejo de excepciones en la aplicacion REST
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

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

        log.error("WebClientResponseException capturado: Status={}, URI={}, ResponseBody={}",ex.getStatusCode(), path, ex.getResponseBodyAsString(), ex);

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

        log.warn("IllegalArgumentException capturada: {}", ex.getMessage(), ex);

        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja las excepciones de tipo {@link MethodArgumentNotValidException}.
     * Estas excepciones se lanzan cuando la validación de un argumento de metodo
     * anotado con Valid o Validated falla.
     *
     * @param ex La excepcion {@link MethodArgumentNotValidException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON los errores de validación
     * y un código de estado HTTP 400 (Bad Request).
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex){
        Map<String, Object> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error ->{
            String fieldName = ((FieldError) error).getField();
            String errorMenssage = error.getDefaultMessage();
            errors.put(fieldName, errorMenssage);
        });

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", new Date());
        errorDetails.put("status", HttpStatus.BAD_REQUEST.value());
        errorDetails.put("error", "Validation Failed");
        errorDetails.put("message", "Uno o mas campos tienen errores de validacion");
        errorDetails.put("details", errors);

        log.warn("MethodArgumentNotValidException capturada: {}", errors, ex);

        return  new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
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

        log.error("Excepcion no capturada: {}", ex.getMessage(), ex);

        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Maneja las excepciones de tipo {@link KeycloakUserCreationException}.
     * Estas excepciones son lanzadas específicamente por KeycloakService
     * cuando hay un problema al interactuar con la API de administración de Keycloak para la creación de usuarios.
     * Se mapea a un 400 Bad Request si el problema es de datos o conflicto, o 500 si es un error interno.
     *
     * @param ex La excepción {@link KeycloakUserCreationException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y un código de estado HTTP 400 (Bad Request) o 409 (Conflict) o 500 (Internal Server Error).
     */
    @ExceptionHandler(KeycloakUserCreationException.class)
    public ResponseEntity<Map<String, Object>> handleKeycloakUserCreationException(KeycloakUserCreationException ex) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", new Date());

        HttpStatus status = HttpStatus.BAD_REQUEST; // Valor por defecto
        String errorMessage = ex.getMessage();

        // Intentar determinar un estado HTTP más específico basado en el mensaje de error
        if (errorMessage != null) {
            if (errorMessage.contains("409 Conflict") || errorMessage.contains("User exists with same username") || errorMessage.contains("User exists with same email")) {
                status = HttpStatus.CONFLICT; // 409 Conflict
                errorDetails.put("error", HttpStatus.CONFLICT.getReasonPhrase());
            } else if (errorMessage.contains("Error interno") || errorMessage.contains("500 Internal Server Error")) {
                status = HttpStatus.INTERNAL_SERVER_ERROR; // 500 Internal Server Error
                errorDetails.put("error", HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
            } else {
                // Si no se detecta un patrón específico, se mantiene BAD_REQUEST
                errorDetails.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
            }
        } else {
            errorDetails.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
        }

        errorDetails.put("status", status.value());
        errorDetails.put("message", errorMessage);

        log.error("KeycloakUserCreationException capturada: Status={}, Message={}", status, ex.getMessage(), ex);

        return new ResponseEntity<>(errorDetails, status);
    }
}
