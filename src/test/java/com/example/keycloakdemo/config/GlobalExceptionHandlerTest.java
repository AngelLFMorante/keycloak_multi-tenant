package com.example.keycloakdemo.config;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.UnknownHttpStatusCodeException;

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
    @DisplayName("Should handle HttpClientErrorException (401 Unauthorized)")
    void handleHttpClientErrorException_Unauthorized() {
        String responseBody = "{\"error\":\"invalid_grant\", \"error_description\":\"Invalid credentials\"}";
        HttpClientErrorException ex = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED,
                "Unauthorized",
                org.springframework.http.HttpHeaders.EMPTY, // Using springframework.http.HttpHeaders
                responseBody.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleHttpClientErrorException(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.UNAUTHORIZED.value(), responseEntity.getBody().get("status"));
        assertEquals("Unauthorized", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Error del cliente al comunicarse con el servicio externo"));
        assertEquals(responseBody, responseEntity.getBody().get("responseBody"));
    }

    @Test
    @DisplayName("Should handle HttpServerErrorException (500 Internal Server Error)")
    void handleHttpServerErrorException_InternalServerError() {
        String responseBody = "{\"error\":\"server_error\", \"message\":\"Keycloak internal error\"}";
        HttpServerErrorException ex = HttpServerErrorException.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                org.springframework.http.HttpHeaders.EMPTY,
                responseBody.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleHttpServerErrorException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseEntity.getBody().get("status"));
        assertEquals("Internal Server Error", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Error del servidor externo"));
        assertEquals(responseBody, responseEntity.getBody().get("responseBody"));
    }

    @Test
    @DisplayName("Should handle ResourceAccessException (Service Unavailable)")
    void handleResourceAccessException_ServiceUnavailable() {
        ResourceAccessException ex = new ResourceAccessException("I/O error on POST request for \"http://keycloak.example.com\": Connection refused (Connection refused)");

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleResourceAccessException(ex);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE.value(), responseEntity.getBody().get("status"));
        assertEquals("Service Unavailable", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Problema de comunicación con el servicio externo"));
    }

    @Test
    @DisplayName("Should handle ResourceAccessException (Gateway Timeout)")
    void handleResourceAccessException_GatewayTimeout() {
        ResourceAccessException ex = new ResourceAccessException("I/O error: Read timed out");

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleResourceAccessException(ex);

        assertEquals(HttpStatus.GATEWAY_TIMEOUT, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.GATEWAY_TIMEOUT.value(), responseEntity.getBody().get("status"));
        assertEquals("Gateway Timeout", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Problema de comunicación con el servicio externo"));
    }

    @Test
    @DisplayName("Should handle UnknownHttpStatusCodeException")
    void handleUnknownHttpStatusCodeException() {
        // Simulating an unknown status code, e.g., 999
        UnknownHttpStatusCodeException ex = new UnknownHttpStatusCodeException(
                999,
                "Unknown Status",
                org.springframework.http.HttpHeaders.EMPTY,
                "Unexpected response".getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleUnknownHttpStatusCodeException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseEntity.getBody().get("status"));
        assertEquals("Internal Server Error", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Servicio externo respondió con código de estado desconocido: 999"));
        assertEquals(999, responseEntity.getBody().get("rawStatusCode"));
        assertEquals("Unexpected response", responseEntity.getBody().get("responseBody"));
    }


    @Test
    @DisplayName("Debería manejar IllegalArgumentException")
    void handleIllegalArgumentException() {
        String errorMessage = "Las contraseñas no coinciden.";
        IllegalArgumentException ex = new IllegalArgumentException(errorMessage);

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleIllegalArgumentException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.BAD_REQUEST.value(), responseEntity.getBody().get("status"));
        assertEquals("Bad Request", responseEntity.getBody().get("error"));
        assertEquals(errorMessage, responseEntity.getBody().get("message"));
    }

    @Test
    @DisplayName("Debería manejar KeycloakUserCreationException (Internal Server Error)")
    void handleKeycloakUserCreationException_InternalServerError() {
        String errorMessage = "Error interno al crear usuario: No se pudo conectar.";
        KeycloakUserCreationException ex = new KeycloakUserCreationException(errorMessage);

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleKeycloakUserCreationException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseEntity.getBody().get("status"));
        assertEquals("Internal Server Error", responseEntity.getBody().get("error"));
        assertEquals(errorMessage, responseEntity.getBody().get("message"));
    }

    @Test
    @DisplayName("Debería manejar KeycloakUserCreationException (Conflict)")
    void handleKeycloakUserCreationException_Conflict() {
        String errorMessage = "Error al crear usuario en Keycloak. Estado HTTP: 409. Detalles: User exists with same username.";
        KeycloakUserCreationException ex = new KeycloakUserCreationException(errorMessage);

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleKeycloakUserCreationException(ex);

        assertEquals(HttpStatus.CONFLICT, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.CONFLICT.value(), responseEntity.getBody().get("status"));
        assertEquals("Conflict", responseEntity.getBody().get("error"));
        assertEquals(errorMessage, responseEntity.getBody().get("message"));
    }

    @Test
    @DisplayName("Debería manejar MethodArgumentNotValidException")
    void handleValidationExceptions() {
        FieldError fieldError1 = new FieldError("registerRequest", "username", "El nombre de usuario no puede estar vacio");
        FieldError fieldError2 = new FieldError("registerRequest", "email", "El email debe tener un formato valido");
        List<FieldError> fieldErrors = Arrays.asList(fieldError1, fieldError2);

        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        when(ex.getBindingResult()).thenReturn(bindingResult);

        when(bindingResult.getAllErrors()).thenReturn(Collections.unmodifiableList(fieldErrors));

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleValidationExceptions(ex);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.BAD_REQUEST.value(), responseEntity.getBody().get("status"));
        assertEquals("Validation Failed", responseEntity.getBody().get("error"));

        assertTrue(responseEntity.getBody().get("message").toString().contains("Uno o mas campos tienen errores de validacion"));

        Map<String, String> details = (Map<String, String>) responseEntity.getBody().get("details");
        assertNotNull(details);
        assertEquals("El nombre de usuario no puede estar vacio", details.get("username"));
        assertEquals("El email debe tener un formato valido", details.get("email"));
    }

    @Test
    @DisplayName("Debería manejar cualquier otra Exception genérica")
    void handleAllUncaughtException() {
        String errorMessage = "Algo salió muy mal.";
        Exception ex = new RuntimeException(errorMessage);

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleAllUncaughtException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseEntity.getBody().get("status"));
        assertEquals("Internal Server Error", responseEntity.getBody().get("error"));
        assertEquals("Ocurrió un error inesperado. Por favor, intente de nuevo mas tarde.", responseEntity.getBody().get("message"));
    }
}