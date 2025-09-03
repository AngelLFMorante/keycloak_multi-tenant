package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.exception.KeycloakCommunicationException;
import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.ErrorResponse;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
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
 * <p>
 * Utiliza {@link ControllerAdvice} para centralizar el manejo de excepciones
 * de la aplicación en una sola clase, proporcionando respuestas HTTP consistentes
 * y útiles para el cliente.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // --- Manejo de Excepciones Específicas de Keycloak ---

    /**
     * Maneja las excepciones de tipo {@link KeycloakCommunicationException}.
     * <p>
     * Estas excepciones se lanzan cuando hay un error de comunicación con Keycloak,
     * como un error de red o un error inesperado del servidor.
     *
     * @param ex La excepción {@link KeycloakCommunicationException} capturada.
     * @return Un {@link ResponseEntity} con un objeto {@link ErrorResponse} y
     * un código de estado HTTP 500 (Internal Server Error).
     */
    @ExceptionHandler(KeycloakCommunicationException.class)
    public ResponseEntity<ErrorResponse> handleKeycloakCommunicationException(KeycloakCommunicationException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "Error de comunicación con el servicio Keycloak: " + ex.getMessage(),
                null
        );

        log.error("KeycloakCommunicationException capturada: {}", ex.getMessage(), ex);
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Maneja las excepciones de tipo {@link KeycloakUserCreationException}.
     * <p>
     * Estas excepciones se lanzan cuando hay un problema al interactuar con la API
     * de administración de Keycloak para la creación de usuarios. El método mapea el
     * error a un código de estado apropiado (400, 409 o 500) basado en el mensaje
     * de la excepción.
     *
     * @param ex La excepción {@link KeycloakUserCreationException} capturada.
     * @return Un {@link ResponseEntity} con el error mapeado a un código de estado
     * HTTP 400 (Bad Request), 409 (Conflict) o 500 (Internal Server Error).
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

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Maneja las excepciones de tipo {@link KeycloakRoleCreationException}.
     * <p>
     * Estas excepciones son lanzadas cuando hay un problema al crear roles en Keycloak.
     * El método adapta el código de estado HTTP basándose en el mensaje de error para
     * ofrecer una respuesta precisa (400, 409 o 500).
     *
     * @param ex La excepción {@link KeycloakRoleCreationException} capturada.
     * @return Un {@link ResponseEntity} con el error mapeado a un código de estado
     * HTTP 400 (Bad Request), 409 (Conflict) o 500 (Internal Server Error).
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

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Manejador global para la excepción {@link NotFoundException}.
     * <p>
     * Este método se encarga de interceptar cualquier {@code NotFoundException}
     * lanzada en los controladores y la transforma en una respuesta HTTP
     * estandarizada con un código de estado 404 Not Found.
     *
     * @param ex La excepción {@link NotFoundException} que fue capturada.
     * @return Una {@link ResponseEntity} que contiene un objeto {@link ErrorResponse}
     * con los detalles del error y un código de estado HTTP 404.
     */
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFoundException(NotFoundException ex) {
        log.warn("Se ha capturado una NotFoundException. Mensaje: {}", ex.getMessage());

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                HttpStatus.NOT_FOUND.value(),
                HttpStatus.NOT_FOUND.getReasonPhrase(),
                "El recurso solicitado no fue encontrado: " + ex.getMessage(),
                null
        );

        log.debug("Generando respuesta de error 404 Not Found para la excepción: {}", ex.getClass().getName());
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    /**
     * Maneja las excepciones de tipo {@link ClientErrorException} (errores 4xx) del cliente de Keycloak Admin.
     * <p>
     * Estas excepciones son lanzadas por el cliente JAX-RS cuando Keycloak responde con un código de estado de cliente.
     *
     * @param ex La excepción {@link ClientErrorException} capturada.
     * @return Un {@link ResponseEntity} con los detalles del error y el código de estado 4xx.
     */
    @ExceptionHandler(ClientErrorException.class)
    public ResponseEntity<ErrorResponse> handleClientErrorException(ClientErrorException ex) {
        int statusCode = ex.getResponse().getStatus();
        HttpStatus httpStatus = HttpStatus.resolve(statusCode);
        String reasonPhrase = httpStatus != null ? httpStatus.getReasonPhrase() : "Unknown Client Error";

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                statusCode,
                reasonPhrase,
                "Error del cliente al interactuar con la API de Keycloak: " + ex.getMessage(),
                null
        );

        log.error("ClientErrorException capturada: Status={}, Mensaje={}", statusCode, ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.valueOf(statusCode));
    }

    /**
     * Maneja las excepciones de tipo {@link ServerErrorException} (errores 5xx) del cliente de Keycloak Admin.
     * <p>
     * Estas excepciones son lanzadas por el cliente JAX-RS cuando Keycloak responde con un código de estado de servidor.
     *
     * @param ex La excepción {@link ServerErrorException} capturada.
     * @return Un {@link ResponseEntity} con los detalles del error y el código de estado 5xx.
     */
    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<ErrorResponse> handleServerErrorException(ServerErrorException ex) {
        int statusCode = ex.getResponse().getStatus();
        HttpStatus httpStatus = HttpStatus.resolve(statusCode);
        String reasonPhrase = httpStatus != null ? httpStatus.getReasonPhrase() : "Unknown Server Error";

        ErrorResponse errorResponse = new ErrorResponse(
                new Date(),
                statusCode,
                reasonPhrase,
                "Error del servidor de Keycloak: " + ex.getMessage(),
                null
        );

        log.error("ServerErrorException capturada: Status={}, Mensaje={}", statusCode, ex.getMessage(), ex);

        return new ResponseEntity<>(errorResponse, HttpStatus.valueOf(statusCode));
    }


    // --- Manejo de Excepciones de Spring y RestTemplate ---

    /**
     * Maneja las excepciones de tipo {@link HttpClientErrorException} (errores 4xx).
     * <p>
     * Estas excepciones son lanzadas por RestTemplate cuando el servidor externo
     * responde con un código de estado de cliente (4xx).
     *
     * @param ex La excepción {@link HttpClientErrorException} capturada.
     * @return Un {@link ResponseEntity} que describe el error con el código de estado HTTP 4xx correspondiente.
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
     * <p>
     * Estas excepciones son lanzadas por RestTemplate cuando el servidor externo
     * responde con un código de estado de servidor (5xx).
     *
     * @param ex La excepción {@link HttpServerErrorException} capturada.
     * @return Un {@link ResponseEntity} que describe el error con el código de estado HTTP 5xx correspondiente.
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
     * <p>
     * Estas excepciones son lanzadas por RestTemplate cuando hay problemas de red,
     * como un servidor no disponible o un timeout de conexión.
     *
     * @param ex La excepción {@link ResourceAccessException} capturada.
     * @return Un {@link ResponseEntity} que describe el error con un código de estado
     * HTTP 503 (Service Unavailable) o 504 (Gateway Timeout) dependiendo de la causa.
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
     * <p>
     * Esta excepción se lanza por RestTemplate cuando recibe un código de estado HTTP
     * que no puede mapear a un {@link HttpStatus} conocido.
     *
     * @param ex La excepción {@link UnknownHttpStatusCodeException} capturada.
     * @return Un {@link ResponseEntity} que describe el error con un código de estado HTTP 500.
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
     * Maneja las excepciones de tipo {@link ResponseStatusException}.
     * <p>
     * Estas excepciones son lanzadas explícitamente en los controladores
     * para indicar un estado HTTP y un mensaje de error específicos.
     *
     * @param ex La excepción {@link ResponseStatusException} capturada.
     * @return Un {@link ResponseEntity} que describe el error con el código de estado
     * HTTP especificado en la excepción.
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

    // --- Manejo de Excepciones de Validación y Genéricas ---


    /**
     * Maneja las excepciones de tipo {@link IllegalArgumentException}.
     * <p>
     * Estas excepciones se lanzan cuando los argumentos de entrada no son válidos.
     *
     * @param ex La excepción {@link IllegalArgumentException} capturada.
     * @return Un {@link ResponseEntity} con el error mapeado a un código de estado
     * HTTP 400 (Bad Request).
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
     * <p>
     * Estas excepciones se lanzan cuando la validación de un argumento de método
     * anotado con `@Valid` o `@Validated` falla.
     *
     * @param ex La excepción {@link MethodArgumentNotValidException} capturada.
     * @return Un {@link ResponseEntity} con los errores de validación y un código
     * de estado HTTP 400 (Bad Request).
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
     * Maneja cualquier otra excepción no capturada por los manejadores específicos.
     * <p>
     * Proporciona un mensaje de error genérico para evitar exponer detalles internos
     * del sistema al cliente.
     *
     * @param ex La excepción genérica {@link Exception} capturada.
     * @return Un {@link ResponseEntity} que describe el error y un código de estado HTTP 500.
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

}