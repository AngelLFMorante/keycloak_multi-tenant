package com.example.keycloakdemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.keycloakdemo.config.SecurityConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito; // Importar Mockito para lenient()
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodySpec;
import org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec;
import org.springframework.web.reactive.function.client.WebClient.RequestHeadersSpec;
import org.springframework.web.reactive.function.client.WebClient.ResponseSpec;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link LoginController}.
 * Utiliza Mockito para aislar el controlador y probar su lógica de negocio
 * sin cargar el contexto completo de Spring Boot.
 */
@ExtendWith(MockitoExtension.class)
class LoginControllerUnitTest {

    @InjectMocks
    private LoginController loginController;

    @Mock
    private WebClient.Builder webClientBuilder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private SecurityContextRepository securityContextRepository;

    @Mock
    private WebClient webClient;

    @Mock
    private Map<String, String> clientSecrets;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    private String testTenantIdentifier = "plexus";
    private String testKeycloakClientId = "plexus-app-client";
    private String testUsername = "testuser";
    private String testPassword = "password123";

    private String mockAccessToken = "mockAccessToken";
    private String mockIdToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImVtYWlsIjoidGVzdHVzZXJAZXhhbXBsZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0dXNlciIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1c2VyX2FwcCJdfSwicmVzb3VyY2VfYWNjZXNzIjp7InBsZXh1cy1hcHAtY2xpZW50Ijp7InJvbGVzIjpbImNsaWVudF9yb2xlIl19fX0.signature";

    private String keycloakBaseUrl = "http://localhost:8080";
    private String singleKeycloakRealm = "plexus";

    @BeforeEach
    void setUp() {
        // Configurar el mock de WebClient.Builder para que devuelva el mock de WebClient
        Mockito.lenient().when(webClientBuilder.build()).thenReturn(webClient); // Lenient

        // Inyectar los valores @Value y el mock de WebClient en la instancia del controlador
        // Estos campos no se inyectan automáticamente por @InjectMocks si no están en el constructor
        ReflectionTestUtils.setField(loginController, "keycloakBaseUrl", keycloakBaseUrl);
        ReflectionTestUtils.setField(loginController, "singleKeycloakRealm", singleKeycloakRealm);
        ReflectionTestUtils.setField(loginController, "clientSecrets", clientSecrets);
        ReflectionTestUtils.setField(loginController, "webClient", webClient);

        // Configurar el SecurityContextHolder para el test
        SecurityContextHolder.setContext(mock(SecurityContext.class));
        Mockito.lenient().when(SecurityContextHolder.getContext().getAuthentication()).thenReturn(mock(Authentication.class)); // Lenient

        // Configurar el comportamiento por defecto de clientSecrets para los tests que esperan éxito
        Mockito.lenient().when(clientSecrets.get(eq(testKeycloakClientId))).thenReturn("mock-client-secret"); // Lenient
    }

    // Método auxiliar para configurar el encadenamiento de WebClient en cada test
    // CAMBIO: Ahora devuelve RequestHeadersSpec para que los tests de error puedan configurar retrieve().thenThrow()
    private RequestHeadersSpec setupWebClientMockChain() {
        RequestBodyUriSpec requestBodyUriSpec = mock(RequestBodyUriSpec.class);
        RequestBodySpec requestBodySpec = mock(RequestBodySpec.class);
        RequestHeadersSpec requestHeadersSpec = mock(RequestHeadersSpec.class);
        // ResponseSpec responseSpec = mock(ResponseSpec.class); // No se mockea aquí, se mockea en el test individual si es necesario

        // Configurar el comportamiento de los mocks en la cadena
        Mockito.lenient().when(webClient.post()).thenReturn(requestBodyUriSpec);
        Mockito.lenient().when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        Mockito.lenient().when(requestBodySpec.headers(any())).thenReturn(requestBodySpec);
        Mockito.lenient().when(requestBodySpec.contentType(any(MediaType.class))).thenReturn(requestBodySpec);
        Mockito.lenient().when(requestBodySpec.body(any(BodyInserter.class))).thenReturn(requestHeadersSpec);
        // Mockito.lenient().when(requestHeadersSpec.retrieve()).thenReturn(responseSpec); // Esto se configura en cada test
        return requestHeadersSpec; // Devolver el RequestHeadersSpec para configuración posterior
    }

    @Test
    @DisplayName("Debería realizar un login exitoso y retornar 200 OK")
    void doLogin_Success() throws Exception {
        RequestHeadersSpec requestHeadersSpec = setupWebClientMockChain(); // Obtener el RequestHeadersSpec
        ResponseSpec responseSpec = mock(ResponseSpec.class); // Mockear ResponseSpec aquí
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec); // Configurar retrieve para este test

        // Asegurarse de que el JSON de respuesta incluya expiresIn y refreshExpiresIn
        String keycloakResponseJson = String.format(
                "{\"access_token\":\"%s\",\"id_token\":\"%s\",\"refresh_token\":\"mockRefreshToken\",\"expires_in\":3600,\"refresh_expires_in\":1800}",
                mockAccessToken, mockIdToken
        );
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(keycloakResponseJson));

        Authentication authenticatedAuth = new UsernamePasswordAuthenticationToken(
                testUsername, SecurityConfig.DUMMY_PASSWORD, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER_APP"))
        );
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authenticatedAuth);
        doNothing().when(securityContextRepository).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));

        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(
                testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response);

        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals("Login successful", responseEntity.getBody().get("message"));
        assertEquals(testUsername, responseEntity.getBody().get("username"));
        assertEquals("testuser@example.com", responseEntity.getBody().get("email"));
        assertEquals("Test User", responseEntity.getBody().get("fullName"));
        List<String> roles = (List<String>) responseEntity.getBody().get("roles");
        assertNotNull(roles);
        assertTrue(roles.contains("ROLE_USER_APP"));
        assertTrue(roles.contains("ROLE_CLIENT_ROLE"));
        assertEquals(mockAccessToken, responseEntity.getBody().get("accessToken"));
        assertEquals(mockIdToken, responseEntity.getBody().get("idToken"));
        // CAMBIO: Asegurarse de que el valor sea un Long para la aserción
        assertEquals(3600L, responseEntity.getBody().get("expiresIn"));
        assertEquals(1800L, responseEntity.getBody().get("refreshExpiresIn"));
        assertEquals(testTenantIdentifier, responseEntity.getBody().get("realm"));
        assertEquals(testKeycloakClientId, responseEntity.getBody().get("client"));

        verify(webClient, times(1)).post();
        verify(responseSpec, times(1)).bodyToMono(String.class);
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, times(1)).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería retornar 400 Bad Request si el client secret no se encuentra")
    void doLogin_ClientSecretNotFound_ReturnsBadRequest() throws Exception {
        // Configurar el mock de clientSecrets para que devuelva null
        when(clientSecrets.get(eq(testKeycloakClientId))).thenReturn(null);

        // Capturar la excepción esperada
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> loginController.doLogin(testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response),
                "Se esperaba una IllegalArgumentException cuando el secreto del cliente no se encuentra."
        );

        // Verificar el mensaje de la excepción
        String expectedMessage = "Client ID configurado pero secreto no encontrado para: " + testKeycloakClientId + ".Asegurate de que el client ID esté configurado en 'keycloak.client-secrets' en properties.";
        assertEquals(expectedMessage, thrown.getMessage());

        // Verificar que no hubo interacciones con WebClient o Spring Security
        verify(webClient, never()).post();
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería retornar 401 Unauthorized para credenciales inválidas de Keycloak")
    void doLogin_KeycloakReturns401_ReturnsUnauthorized() throws Exception {
        RequestHeadersSpec requestHeadersSpec = setupWebClientMockChain(); // Obtener el RequestHeadersSpec

        WebClientResponseException unauthorizedException = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(), "Unauthorized", HttpHeaders.EMPTY, "{\"error\":\"invalid_grant\"}".getBytes(), StandardCharsets.UTF_8, null);
        // CAMBIO: Configurar retrieve() para lanzar la excepción directamente
        when(requestHeadersSpec.retrieve()).thenThrow(unauthorizedException);

        // Llamar directamente al método del controlador, que ahora lanzará la excepción
        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(
                testTenantIdentifier, testKeycloakClientId, testUsername, "wrongpassword", request, response);

        assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals("Error de autenticación: Usuario o cliente no autorizado con Keycloak.", responseEntity.getBody().get("error"));
        assertEquals("{\"error\":\"invalid_grant\"}", responseEntity.getBody().get("details"));

        verify(webClient, times(1)).post();
        // verify(responseSpec, times(1)).bodyToMono(String.class); // No se verifica bodyToMono si retrieve lanza directamente
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería retornar 500 Internal Server Error para errores inesperados de Keycloak")
    void doLogin_KeycloakReturns500_ReturnsInternalServerError() throws Exception {
        RequestHeadersSpec requestHeadersSpec = setupWebClientMockChain(); // Obtener el RequestHeadersSpec

        WebClientResponseException internalServerErrorException = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error", HttpHeaders.EMPTY, "{\"error\":\"server_error\"}".getBytes(), StandardCharsets.UTF_8, null);
        // CAMBIO: Configurar retrieve() para lanzar la excepción directamente
        when(requestHeadersSpec.retrieve()).thenThrow(internalServerErrorException);

        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(
                testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals("Error de Keycloak: 500 - Internal Server Error", responseEntity.getBody().get("error"));
        assertEquals("{\"error\":\"server_error\"}", responseEntity.getBody().get("details"));

        verify(webClient, times(1)).post();
        // verify(responseSpec, times(1)).bodyToMono(String.class); // No se verifica bodyToMono si retrieve lanza directamente
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería retornar 500 Internal Server Error si la respuesta JSON de Keycloak es inválida")
    void doLogin_InvalidJsonResponse_ReturnsInternalServerError() throws Exception {
        RequestHeadersSpec requestHeadersSpec = setupWebClientMockChain(); // Obtener el RequestHeadersSpec
        ResponseSpec responseSpec = mock(ResponseSpec.class); // Mockear ResponseSpec aquí
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec); // Configurar retrieve para este test

        String invalidJson = "Esto no es JSON válido";
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(invalidJson));

        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(
                testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        String errorMessage = responseEntity.getBody().get("error").toString();
        assertTrue(errorMessage.contains("Unrecognized token 'Esto'"), "El mensaje de error debería indicar token no reconocido.");
        assertTrue(errorMessage.contains("was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')"), "El mensaje de error debería indicar el formato JSON esperado.");

        verify(webClient, times(1)).post();
        verify(responseSpec, times(1)).bodyToMono(String.class);
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }
}