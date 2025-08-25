package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.ErrorResponse;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.UnknownHttpStatusCodeException;
import org.springframework.web.server.ResponseStatusException;

/**
 * Clase global para el manejo de excepciones en la aplicación REST.
 * Utiliza {@link ControllerAdvice} para centralizar el manejo de excepciones
 * de la aplicación en una sola clase, proporcionando respuestas HTTP consistentes
 * y útiles para el cliente.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);


    /**
     * Maneja las excepciones de tipo {@link HttpClientErrorException} (errores 4xx).
     * Estas excepciones son lanzadas por RestTemplate cuando el servidor externo
     * responde con un código de estado de cliente (4xx).
     *
     * @param ex La excepción {@link HttpClientErrorException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y el código de estado HTTP 4xx correspondiente.
     */
    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<ErrorResponse> handleHttpClientErrorException(HttpClientErrorException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                ex.getStatusCode().value(),
                ex.getStatusText(),
                "Error del cliente al comunicarse con el servicio externo: " + ex.getMessage(),
                null
        );

        log.error("HttpClientErrorException capturado: Status={}, Message={}, ResponseBody={}",
                ex.getStatusCode(), ex.getMessage(), ex.getResponseBodyAsString(), ex);

        return new ResponseEntity<>(errorResponse, ex.getStatusCode());
    }

    /**
     * Maneja las excepciones de tipo {@link HttpServerErrorException} (errores 5xx).
     * Estas excepciones son lanzadas por RestTemplate cuando el servidor externo
     * responde con un código de estado de servidor (5xx).
     *
     * @param ex La excepción {@link HttpServerErrorException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y el código de estado HTTP 5xx correspondiente.
     */
    @ExceptionHandler(HttpServerErrorException.class)
    public ResponseEntity<ErrorResponse> handleHttpServerErrorException(HttpServerErrorException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                ex.getStatusCode().value(),
                ex.getStatusText(),
                "Error del servidor externo: " + ex.getMessage(),
                null
        );

        log.error("HttpServerErrorException capturado: Status={}, Message={}, ResponseBody={}",
                ex.getStatusCode(), ex.getMessage(), ex.getResponseBodyAsString(), ex);

        return new ResponseEntity<>(errorResponse, ex.getStatusCode());
    }

    /**
     * Maneja las excepciones de tipo {@link ResourceAccessException}.
     * Estas excepciones son lanzadas por RestTemplate cuando hay problemas de red,
     * como un servidor no disponible, timeout de conexión, etc.
     *
     * @param ex La excepción {@link ResourceAccessException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y un código de estado HTTP 503 (Service Unavailable) o 504 (Gateway Timeout)
     * dependiendo de la causa subyacente.
     */
    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<ErrorResponse> handleResourceAccessException(ResourceAccessException ex) {
        HttpStatus status = HttpStatus.SERVICE_UNAVAILABLE;
        if (ex.getMessage() != null && ex.getMessage().toLowerCase().contains("timeout")) {
            status = HttpStatus.GATEWAY_TIMEOUT;
        }

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                status.value(),
                status.getReasonPhrase(),
                "Problema de comunicacion con el servicio externo: " + ex.getMessage(),
                null
        );

        log.error("ResourceAccessException capturado: Message={}", ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Maneja las excepciones de tipo {@link UnknownHttpStatusCodeException}.
     * Esta excepción es lanzada por RestTemplate cuando recibe un código de estado HTTP
     * que no puede mapear a un {@link HttpStatus} conocido.
     *
     * @param ex La excepción {@link UnknownHttpStatusCodeException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y un código de estado HTTP 500 (Internal Server Error).
     */
    @ExceptionHandler(UnknownHttpStatusCodeException.class)
    public ResponseEntity<ErrorResponse> handleUnknownHttpStatusCodeException(UnknownHttpStatusCodeException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "Servicio externo respondio con codigo de estado desconocido: " + ex.getRawStatusCode(),
                null
        );

        log.error("UnknownHttpStatusCodeException capturado: RawStatus={}, Message={}, ResponseBody={}",
                ex.getRawStatusCode(), ex.getMessage(), ex.getResponseBodyAsString(), ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Maneja las excepciones de tipo {@link IllegalArgumentException}
     * Argumentos de entrada no validas
     *
     * @param ex la excepcion {@link IllegalArgumentException} capturada.
     * @return un {@link ResponseEntity} con un mapa JSon que describe el error
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                ex.getMessage(),
                null
        );

        log.warn("IllegalArgumentException capturada: {}", ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
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
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, Object> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMenssage = error.getDefaultMessage();
            errors.put(fieldName, errorMenssage);
        });

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                "Uno o mas campos tienen errores de validacion",
                errors
        );

        log.warn("MethodArgumentNotValidException capturada: {}", errors, ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Maneja cualquier otra excecion no capturada por los manejadores especificos.
     * Proporciona un mensaje de error generico para evitar exponer detalles internos
     *
     * @param ex La excepcion {@link Exception} generica capturada.
     * @return Un {@link ResponseEntity} describe el rror y codigo de estado Http 500
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAllUncaughtException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "Ocurrio un error inesperado. Por favor, intente de nuevo mas tarde.",
                null
        );

        log.error("Excepcion no capturada: {}", ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
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
    public ResponseEntity<ErrorResponse> handleKeycloakUserCreationException(KeycloakUserCreationException ex) {
        String errorMessage = ex.getMessage();
        HttpStatus status = HttpStatus.BAD_REQUEST;

        if (errorMessage != null) {
            if (errorMessage.contains("409 Conflict") || errorMessage.contains("User exists with same username") || errorMessage.contains("User exists with same email")) {
                status = HttpStatus.CONFLICT;
            } else if (errorMessage.contains("Error interno") || errorMessage.contains("500 Internal Server Error")) {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
            }
        }
        log.error("KeycloakUserCreationException capturada: Status={}, Message={}", status, ex.getMessage(), ex);

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                status.value(),
                status.getReasonPhrase(),
                errorMessage,
                null
        );

        log.error("KeycloakUserCreationException capturada: Status={}, Message={}", status, ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Maneja las excepciones de tipo {@link KeycloakRoleCreationException}.
     * Estas excepciones son lanzadas específicamente por KeycloakService
     * cuando hay un problema al interactuar con la API de administración de Keycloak para la creación de roles.
     * Se mapea a un 400 Bad Request si el problema es de datos o conflicto, o 500 si es un error interno.
     *
     * @param ex La excepción {@link KeycloakRoleCreationException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y un código de estado HTTP 400 (Bad Request) o 409 (Conflict) o 500 (Internal Server Error).
     */
    @ExceptionHandler(KeycloakRoleCreationException.class)
    public ResponseEntity<ErrorResponse> handleKeycloakRoleCreationException(KeycloakRoleCreationException ex) {
        String errorMessage = ex.getMessage();
        HttpStatus status = HttpStatus.BAD_REQUEST;

        if (errorMessage != null) {
            if (errorMessage.contains("409 Conflict") || errorMessage.contains("Role exists with same name")) {
                status = HttpStatus.CONFLICT;
            } else if (errorMessage.contains("Error interno") || errorMessage.contains("500 Internal Server Error")) {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
            }
        }
        log.error("KeycloakRoleCreationException capturada: Status={}, Message={}", status, ex.getMessage(), ex);

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                status.value(),
                status.getReasonPhrase(),
                errorMessage,
                null
        );
        log.error("KeycloakRoleCreationException capturada: Status={}, Message={}", status, ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Maneja las excepciones de tipo {@link ResponseStatusException}.
     * Estas excepciones son lanzadas explícitamente en los controladores
     * para indicar un estado HTTP y un mensaje de error específicos.
     *
     * @param ex La excepción {@link ResponseStatusException} capturada.
     * @return Un {@link ResponseEntity} con un mapa JSON que describe el error
     * y el código de estado HTTP especificado en la excepción.
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ErrorResponse> handleResponseStatusException(ResponseStatusException ex) {
        int statusCode = ex.getStatusCode().value();
        HttpStatus httpStatus = HttpStatus.resolve(statusCode);
        String reasonPhrase = httpStatus != null ? httpStatus.getReasonPhrase() : "Unknown Status";

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                statusCode,
                reasonPhrase,
                ex.getReason() != null ? ex.getReason() : "No message available",
                null
        );

        log.warn("ResponseStatusException capturada: Status={}, Reason={}", ex.getStatusCode(), ex.getReason(), ex);

        return new ResponseEntity<>(errorResponse, ex.getStatusCode());
    }
}
