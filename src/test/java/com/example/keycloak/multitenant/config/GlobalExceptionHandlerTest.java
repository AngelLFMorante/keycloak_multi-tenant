package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.exception.KeycloakCommunicationException;
import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.ErrorResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.UnknownHttpStatusCodeException;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link GlobalExceptionHandler}.
 * Verifica que los métodos de manejo de excepciones globales capturan
 * y transforman correctamente las excepciones en respuestas HTTP JSON consistentes.
 */
@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Mock
    private BindingResult bindingResult;

    @Test
    @DisplayName("Debería manejar KeycloakCommunicationException")
    void handleKeycloakCommunicationException() {
        String errorMessage = "Problema de conexión con Keycloak.";
        KeycloakCommunicationException ex = new KeycloakCommunicationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakCommunicationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertTrue(errorResponse.message().contains("Error de comunicación con el servicio Keycloak:"));
        assertTrue(errorResponse.message().contains(errorMessage));
    }

    @Test
    @DisplayName("Debería manejar HttpClientErrorException (401 Unauthorized)")
    void handleHttpClientErrorException_Unauthorized() {
        String responseBody = "{\"error\":\"invalid_grant\", \"error_description\":\"Invalid credentials\"}";
        HttpClientErrorException ex = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED,
                "Unauthorized",
                org.springframework.http.HttpHeaders.EMPTY,
                responseBody.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleHttpClientErrorException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.status());
        assertEquals("Unauthorized", errorResponse.error());
        assertTrue(errorResponse.message().contains("Error del cliente al comunicarse con el servicio externo"));
    }

    @Test
    @DisplayName("Debería manejar HttpServerErrorException (500 Internal Server Error)")
    void handleHttpServerErrorException_InternalServerError() {
        String responseBody = "{\"error\":\"server_error\", \"message\":\"Keycloak internal error\"}";
        HttpServerErrorException ex = HttpServerErrorException.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                org.springframework.http.HttpHeaders.EMPTY,
                responseBody.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleHttpServerErrorException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertTrue(errorResponse.message().contains("Error del servidor externo"));
    }

    @Test
    @DisplayName("Debería manejar ResourceAccessException (Service Unavailable)")
    void handleResourceAccessException_ServiceUnavailable() {
        ResourceAccessException ex = new ResourceAccessException("I/O error on POST request for \"http://keycloak.example.com\": Connection refused (Connection refused)");

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleResourceAccessException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE.value(), errorResponse.status());
        assertEquals("Service Unavailable", errorResponse.error());
        assertTrue(errorResponse.message().contains("Problema de comunicacion con el servicio externo"));
    }

    @Test
    @DisplayName("Debería manejar ResourceAccessException (Gateway Timeout)")
    void handleResourceAccessException_GatewayTimeout() {
        ResourceAccessException ex = new ResourceAccessException("Conexión expiró: timeout");

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleResourceAccessException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.GATEWAY_TIMEOUT, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.GATEWAY_TIMEOUT.value(), errorResponse.status());
        assertEquals("Gateway Timeout", errorResponse.error());
        assertTrue(errorResponse.message().contains("Problema de comunicacion con el servicio externo"));
    }

    @Test
    @DisplayName("Debería manejar UnknownHttpStatusCodeException")
    void handleUnknownHttpStatusCodeException() {
        UnknownHttpStatusCodeException ex = new UnknownHttpStatusCodeException(
                999,
                "Unknown Status",
                org.springframework.http.HttpHeaders.EMPTY,
                "Unexpected response".getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleUnknownHttpStatusCodeException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertTrue(errorResponse.message().contains("Servicio externo respondio con codigo de estado desconocido: 999"));
    }

    @Test
    @DisplayName("Debería manejar IllegalArgumentException")
    void handleIllegalArgumentException() {
        String errorMessage = "Las contraseñas no coinciden.";
        IllegalArgumentException ex = new IllegalArgumentException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleIllegalArgumentException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Bad Request", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar KeycloakUserCreationException (Internal Server Error)")
    void handleKeycloakUserCreationException_InternalServerError() {
        String errorMessage = "Error interno al crear usuario: 500 Internal Server Error.";
        KeycloakUserCreationException ex = new KeycloakUserCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakUserCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar KeycloakUserCreationException (Conflict)")
    void handleKeycloakUserCreationException_Conflict() {
        String errorMessage = "Error al crear usuario en Keycloak. Estado HTTP: 409. Detalles: User exists with same username.";
        KeycloakUserCreationException ex = new KeycloakUserCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakUserCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.CONFLICT, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.CONFLICT.value(), errorResponse.status());
        assertEquals("Conflict", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar KeycloakUserCreationException (Bad Request por defecto)")
    void handleKeycloakUserCreationException_BadRequestDefault() {
        String errorMessage = "Datos de usuario inválidos enviados a Keycloak.";
        KeycloakUserCreationException ex = new KeycloakUserCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakUserCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Bad Request", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar MethodArgumentNotValidException")
    void handleValidationExceptions() {
        FieldError fieldError1 = new FieldError("registerRequest", "username", "El nombre de usuario no puede estar vacio");
        FieldError fieldError2 = new FieldError("registerRequest", "email", "El email debe tener un formato valido");
        List<FieldError> fieldErrors = Arrays.asList(fieldError1, fieldError2);

        Method mockMethod = mock(Method.class);
        when(mockMethod.toGenericString()).thenReturn("public void com.example.MyController.myMethod(MyRequest)");

        MethodParameter mockMethodParameter = mock(MethodParameter.class);
        when(mockMethodParameter.getParameterIndex()).thenReturn(0);
        when(mockMethodParameter.getExecutable()).thenReturn(mockMethod);

        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(mockMethodParameter, bindingResult);

        when(bindingResult.getAllErrors()).thenReturn(Collections.unmodifiableList(fieldErrors));

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleValidationExceptions(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Validation Failed", errorResponse.error());
        assertTrue(errorResponse.message().contains("Uno o mas campos tienen errores de validacion"));

        Map<String, String> details = (Map<String, String>) errorResponse.details();
        assertNotNull(details);
        assertEquals("El nombre de usuario no puede estar vacio", details.get("username"));
        assertEquals("El email debe tener un formato valido", details.get("email"));
    }

    @Test
    @DisplayName("Debería manejar ResponseStatusException")
    void handleResponseStatusException() {
        String reason = "Recurso no encontrado";
        HttpStatus status = HttpStatus.NOT_FOUND;
        ResponseStatusException ex = new ResponseStatusException(status, reason);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleResponseStatusException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(status, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(status.value(), errorResponse.status());
        assertEquals(status.getReasonPhrase(), errorResponse.error());
        assertEquals(reason, errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar cualquier otra Exception genérica")
    void handleAllUncaughtException() {
        String errorMessage = "Algo salió muy mal.";
        Exception ex = new RuntimeException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleAllUncaughtException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertEquals("Ocurrio un error inesperado. Por favor, intente de nuevo mas tarde.", errorResponse.message());
    }

    @Test
    @DisplayName("Debería manejar KeycloakRoleCreationException (Conflict 409)")
    void handleKeycloakRoleCreationException_Conflict() {
        String errorMessage = "Error al crear rol en Keycloak. Estado HTTP: 409 Conflict. Detalles: Role exists with same name.";
        KeycloakRoleCreationException ex = new KeycloakRoleCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakRoleCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.CONFLICT, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.CONFLICT.value(), errorResponse.status());
        assertEquals("Conflict", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
        assertNotNull(errorResponse.timestamp());
    }

    @Test
    @DisplayName("Debería manejar KeycloakRoleCreationException (Internal Server Error 500)")
    void handleKeycloakRoleCreationException_InternalServerError() {
        String errorMessage = "Error interno al crear rol: 500 Internal Server Error.";
        KeycloakRoleCreationException ex = new KeycloakRoleCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakRoleCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorResponse.status());
        assertEquals("Internal Server Error", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
        assertNotNull(errorResponse.timestamp());
    }

    @Test
    @DisplayName("Debería manejar KeycloakRoleCreationException (Bad Request 400 por defecto)")
    void handleKeycloakRoleCreationException_BadRequestDefault() {
        String errorMessage = "Datos de rol invalidos enviados a Keycloak.";
        KeycloakRoleCreationException ex = new KeycloakRoleCreationException(errorMessage);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakRoleCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Bad Request", errorResponse.error());
        assertEquals(errorMessage, errorResponse.message());
        assertNotNull(errorResponse.timestamp());
    }

    @Test
    @DisplayName("Debería manejar KeycloakRoleCreationException con mensaje nulo (Bad Request 400)")
    void handleKeycloakRoleCreationException_NullMessage() {
        KeycloakRoleCreationException ex = new KeycloakRoleCreationException(null);

        ResponseEntity<ErrorResponse> responseEntity = globalExceptionHandler.handleKeycloakRoleCreationException(ex);
        ErrorResponse errorResponse = responseEntity.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(errorResponse);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Bad Request", errorResponse.error());
        assertEquals(null, errorResponse.message());
        assertNotNull(errorResponse.timestamp());
    }
}