package com.example.keycloakdemo.config;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

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
    @DisplayName("Debería manejar WebClientResponseException (401 Unauthorized)")
    void handleWebClientResponseException_Unauthorized() {
        // Simular una WebClientResponseException con estado 401
        // No se proporciona URI en el create, por lo que el path será "Desconocido"
        WebClientResponseException ex = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                HttpHeaders.EMPTY,
                "{\"error\":\"invalid_grant\"}".getBytes(),
                null // No se proporciona ClientRequest, por lo que getRequest() será null
        );

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleWebClientResponseException(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.UNAUTHORIZED.value(), responseEntity.getBody().get("status"));
        assertEquals("Unauthorized", responseEntity.getBody().get("error"));
        // Ajustar el mensaje esperado para que coincida con el controlador (sin tilde en comunicacion)
        assertTrue(responseEntity.getBody().get("message").toString().contains("Error en la comunicacion con el servicio externo"));
        assertEquals("{\"error\":\"invalid_grant\"}", responseEntity.getBody().get("responseBody"));
        assertEquals("Desconocido", responseEntity.getBody().get("path")); // CORREGIDO: Espera "Desconocido"
    }

    @Test
    @DisplayName("Debería manejar WebClientResponseException (404 Not Found)")
    void handleWebClientResponseException_NotFound() {
        // Simular una WebClientResponseException con estado 404
        // No se proporciona URI en el create, por lo que el path será "Desconocido"
        WebClientResponseException ex = WebClientResponseException.create(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                HttpHeaders.EMPTY,
                "{\"message\":\"Endpoint not found\"}".getBytes(),
                null // No se proporciona ClientRequest, por lo que getRequest() será null
        );

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleWebClientResponseException(ex);

        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.NOT_FOUND.value(), responseEntity.getBody().get("status"));
        assertEquals("Not Found", responseEntity.getBody().get("error"));
        assertTrue(responseEntity.getBody().get("message").toString().contains("Error en la comunicacion con el servicio externo"));
        assertEquals("{\"message\":\"Endpoint not found\"}", responseEntity.getBody().get("responseBody"));
        assertEquals("Desconocido", responseEntity.getBody().get("path")); // CORREGIDO: Espera "Desconocido"
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
        // Simular FieldErrors
        FieldError fieldError1 = new FieldError("registerRequest", "username", "El nombre de usuario no puede estar vacio");
        FieldError fieldError2 = new FieldError("registerRequest", "email", "El email debe tener un formato valido");
        List<FieldError> fieldErrors = Arrays.asList(fieldError1, fieldError2);

        // Mockear MethodArgumentNotValidException y configurar el BindingResult
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
        Exception ex = new RuntimeException(errorMessage); // Simular una excepción genérica

        ResponseEntity<Map<String, Object>> responseEntity = globalExceptionHandler.handleAllUncaughtException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), responseEntity.getBody().get("status"));
        assertEquals("Internal Server Error", responseEntity.getBody().get("error"));
        assertEquals("Ocurrió un error inesperado. Por favor, intente de nuevo mas tarde.", responseEntity.getBody().get("message"));
    }
}
