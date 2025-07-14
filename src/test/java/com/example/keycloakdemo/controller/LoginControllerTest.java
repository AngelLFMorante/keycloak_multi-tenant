package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.config.KeycloakProperties;
import com.example.keycloakdemo.config.SecurityConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
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
class LoginControllerTest {

    @InjectMocks
    private LoginController loginController;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private SecurityContextRepository securityContextRepository;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private KeycloakProperties keycloakProperties;

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

        SecurityContextHolder.setContext(Mockito.mock(SecurityContext.class));
        Mockito.lenient().when(SecurityContextHolder.getContext().getAuthentication()).thenReturn(Mockito.mock(Authentication.class));

        Mockito.lenient().when(keycloakProperties.getClientSecrets()).thenReturn(Mockito.mock(Map.class));
        Mockito.lenient().when(keycloakProperties.getClientSecrets().get(eq(testKeycloakClientId))).thenReturn("mock-client-secret");
        Mockito.lenient().when(keycloakProperties.getAuthServerUrl()).thenReturn(keycloakBaseUrl);
        Mockito.lenient().when(keycloakProperties.getSingleRealmName()).thenReturn(singleKeycloakRealm);
    }

    @Test
    @DisplayName("Debería realizar un login exitoso y retornar 200 OK")
    void doLogin_Success() throws Exception {
        String keycloakResponseJson = String.format(
                "{\"access_token\":\"%s\",\"id_token\":\"%s\",\"refresh_token\":\"mockRefreshToken\",\"expires_in\":3600,\"refresh_expires_in\":1800}",
                mockAccessToken, mockIdToken
        );

        when(restTemplate.postForEntity(
                anyString(),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(new ResponseEntity<>(keycloakResponseJson, HttpStatus.OK));

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
        assertEquals(3600L, responseEntity.getBody().get("expiresIn"));
        assertEquals(1800L, responseEntity.getBody().get("refreshExpiresIn"));
        assertEquals(testTenantIdentifier, responseEntity.getBody().get("realm"));
        assertEquals(testKeycloakClientId, responseEntity.getBody().get("client"));

        verify(restTemplate, times(1)).postForEntity(anyString(), any(HttpEntity.class), eq(String.class));
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, times(1)).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería retornar 400 Bad Request si el client secret no se encuentra")
    void doLogin_ClientSecretNotFound_ReturnsBadRequest() throws Exception {
        when(keycloakProperties.getClientSecrets().get(eq(testKeycloakClientId))).thenReturn(null);

        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> loginController.doLogin(testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response),
                "Se esperaba una IllegalArgumentException cuando el secreto del cliente no se encuentra."
        );

        String expectedMessage = "Client ID configurado pero secreto no encontrado para: " + testKeycloakClientId + ".Asegurate de que el client ID esté configurado en 'keycloak.client-secrets' en properties.";
        assertEquals(expectedMessage, thrown.getMessage());

        verify(restTemplate, never()).postForEntity(anyString(), any(HttpEntity.class), any());
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería lanzar HttpClientErrorException para credenciales inválidas de Keycloak (401)")
    void doLogin_KeycloakReturns401_ThrowsHttpClientErrorException() throws Exception {
        HttpClientErrorException unauthorizedException = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized", HttpHeaders.EMPTY, "{\"error\":\"invalid_grant\"}".getBytes(), StandardCharsets.UTF_8);

        when(restTemplate.postForEntity(
                anyString(),
                any(HttpEntity.class),
                eq(String.class)
        )).thenThrow(unauthorizedException);

        HttpClientErrorException thrown = assertThrows(
                HttpClientErrorException.class,
                () -> loginController.doLogin(testTenantIdentifier, testKeycloakClientId, testUsername, "wrongpassword", request, response),
                "Se esperaba una HttpClientErrorException para credenciales inválidas."
        );

        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getStatusCode());
        assertTrue(thrown.getResponseBodyAsString().contains("invalid_grant"));

        verify(restTemplate, times(1)).postForEntity(anyString(), any(HttpEntity.class), eq(String.class));
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería lanzar HttpServerErrorException para errores inesperados de Keycloak (500)")
    void doLogin_KeycloakReturns500_ThrowsHttpServerErrorException() throws Exception {
        HttpServerErrorException internalServerErrorException = HttpServerErrorException.create(
                HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", HttpHeaders.EMPTY, "{\"error\":\"server_error\"}".getBytes(), StandardCharsets.UTF_8);

        when(restTemplate.postForEntity(
                anyString(),
                any(HttpEntity.class),
                eq(String.class)
        )).thenThrow(internalServerErrorException);

        HttpServerErrorException thrown = assertThrows(
                HttpServerErrorException.class,
                () -> loginController.doLogin(testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response),
                "Se esperaba una HttpServerErrorException para errores de servidor."
        );

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, thrown.getStatusCode());
        assertTrue(thrown.getResponseBodyAsString().contains("server_error"));

        verify(restTemplate, times(1)).postForEntity(anyString(), any(HttpEntity.class), eq(String.class));
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("Debería lanzar IOException si la respuesta JSON de Keycloak es inválida")
    void doLogin_InvalidJsonResponse_ThrowsIOException() throws Exception {
        String invalidJson = "Esto no es JSON válido";

        when(restTemplate.postForEntity(
                anyString(),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(new ResponseEntity<>(invalidJson, HttpStatus.OK));

        IOException thrown = assertThrows(
                IOException.class,
                () -> loginController.doLogin(testTenantIdentifier, testKeycloakClientId, testUsername, testPassword, request, response),
                "Se esperaba una IOException para JSON inválido."
        );

        assertTrue(thrown.getMessage().contains("Unrecognized token 'Esto'"), "El mensaje de error debería indicar token no reconocido.");

        verify(restTemplate, times(1)).postForEntity(anyString(), any(HttpEntity.class), eq(String.class));
        verify(authenticationManager, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, never()).saveContext(any(SecurityContext.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }
}