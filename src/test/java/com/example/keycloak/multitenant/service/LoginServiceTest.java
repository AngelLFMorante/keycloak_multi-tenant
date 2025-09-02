package com.example.keycloak.multitenant.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakOidcClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


class LoginServiceTest {

    @Mock
    private KeycloakOidcClient keycloakOidcClient;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private LoginService loginService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private String realm;
    private String keycloakRealm;
    private String client;
    private String username;
    private String password;
    private String clientSecret;
    private String refreshTokenValue;
    private Map<String, String> realmMapping;
    private Map<String, String> clientSecrets;
    private String authServerUrl;
    private String issuerUrl;
    private List<String> mockRealmRoles;
    private Map<String, List<String>> mockClientRoles;
    private String mockAccessToken;
    private String mockIdToken;
    private String keycloakTokenResponse;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        realm = "plexus";
        keycloakRealm = "plexus-realm";
        client = "mi-app-plexus";
        username = "testuser";
        password = "testpassword";
        clientSecret = "mock-client-secret";
        refreshTokenValue = "some-refresh-token";
        realmMapping = new HashMap<>();
        realmMapping.put(realm, keycloakRealm);
        clientSecrets = new HashMap<>();
        clientSecrets.put(client, clientSecret);

        authServerUrl = "http://localhost:8080";
        issuerUrl = authServerUrl + "/realms/" + keycloakRealm;

        mockRealmRoles = List.of("app_users", "offline_access");
        mockClientRoles = new HashMap<>();
        mockClientRoles.put(client, List.of("user_app"));
        mockAccessToken = createMockJwt(username, "test@example.com", "Test User", mockRealmRoles, mockClientRoles, issuerUrl);
        mockIdToken = createMockJwt(username, "test@example.com", "Test User", Collections.emptyList(), Collections.emptyMap(), issuerUrl);
        keycloakTokenResponse = "{" +
                "\"access_token\":\"" + mockAccessToken + "\"," +
                "\"id_token\":\"" + mockIdToken + "\"," +
                "\"refresh_token\":\"" + refreshTokenValue + "\"," +
                "\"expires_in\":300," +
                "\"refresh_expires_in\":1800" +
                "}";

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);
        when(keycloakOidcClient.createBasicAuthHeaders(anyString(), anyString())).thenReturn(new HttpHeaders());
    }

    private String createMockJwt(String username, String email, String fullName, List<String> realmRoles, Map<String, List<String>> clientRoles, String issuer) {
        try {
            Map<String, Object> headerClaims = new HashMap<>();
            headerClaims.put("alg", "HS256");
            headerClaims.put("typ", "JWT");

            Map<String, Object> payloadClaims = new HashMap<>();
            payloadClaims.put("sub", "54321");
            payloadClaims.put("name", fullName);
            payloadClaims.put("preferred_username", username);
            payloadClaims.put("email", email);
            payloadClaims.put("iss", issuer);

            Map<String, Object> realmAccessClaim = new HashMap<>();
            realmAccessClaim.put("roles", realmRoles);
            payloadClaims.put("realm_access", realmAccessClaim);

            Map<String, Object> resourceAccessClaim = new HashMap<>();
            clientRoles.forEach((clientId, rolesList) -> {
                Map<String, Object> clientAccess = new HashMap<>();
                clientAccess.put("roles", rolesList);
                resourceAccessClaim.put(clientId, clientAccess);
            });
            payloadClaims.put("resource_access", resourceAccessClaim);

            String header = objectMapper.writeValueAsString(headerClaims);
            String payload = objectMapper.writeValueAsString(payloadClaims);

            String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
            String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());

            return encodedHeader + "." + encodedPayload + ".mocksignature";
        } catch (Exception e) {
            throw new RuntimeException("Error creating mock JWT", e);
        }
    }

    @Test
    void testAuthenticateSuccess() throws Exception {
        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("token"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(String.class)
        )).thenReturn(keycloakTokenResponse);

        LoginResponse response = loginService.authenticate(realm, client, username, password);

        List<String> actualRoles = response.getRoles();

        assertNotNull(response);
        assertNotNull(actualRoles);
        assertTrue(actualRoles.contains("ROLE_APP_USERS"));
        assertTrue(actualRoles.contains("ROLE_OFFLINE_ACCESS"));
        assertTrue(actualRoles.contains("ROLE_USER_APP"));

        assertNotNull(response.getAccessToken());
        assertNotNull(response.getIdToken());
        assertNotNull(response.getRefreshToken());
        assertEquals(300L, response.getExpiresIn());
        assertEquals(1800L, response.getRefreshExpiresIn());
        assertEquals(realm, response.getRealm());
        assertEquals(client, response.getClient());
        assertEquals(username, response.getPreferredUsername());

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakProperties, times(1)).getClientSecrets();
        verify(keycloakOidcClient, times(1)).postRequest(anyString(), anyString(), any(), any(), eq(String.class));
    }

    @Test
    void testAuthenticateTenantNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> loginService.authenticate("unknown", "client", "user", "pass"));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
    }

    @Test
    void authenticate_clientSecretIsNull_throwsIllegalArgumentException() {
        clientSecrets.remove(client);
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
        assertTrue(exception.getMessage().contains("secreto no encontrado"));
    }

    @Test
    void authenticate_httpClientErrorException_throwsResponseStatusException() {
        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(httpEx);

        assertThrows(HttpClientErrorException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    void authenticate_unexpectedException_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Unexpected"));

        assertThrows(RuntimeException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    void authenticate_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenReturn("invalid-json");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al procesar la respuesta de Keycloak.", exception.getReason());
    }

    @Test
    void testRefreshTokenSuccess() throws Exception {
        String oldRefreshToken = "old-token";
        String tokenJson = "{" +
                "\"access_token\": \"new-access-token\"," +
                "\"refresh_token\": \"new-refresh-token\"," +
                "\"expires_in\": 3000," +
                "\"refresh_expires_in\": 18000," +
                "\"id_token\": \"new-id-token\"}";

        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("token"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(String.class)
        )).thenReturn(tokenJson);

        LoginResponse response = loginService.refreshToken(oldRefreshToken, realm, client);

        assertNotNull(response);
        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());
        assertEquals(3000L, response.getExpiresIn());
        assertEquals(18000L, response.getRefreshExpiresIn());
    }

    @Test
    void refreshToken_realmNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("token", "unknownRealm", "testClient"));
    }

    @Test
    void refreshToken_clientSecretMissing() {
        clientSecrets.remove(client);
        assertThrows(IllegalArgumentException.class, () ->
                loginService.refreshToken("token", realm, client));
    }

    @Test
    void refreshToken_exceptionThrown() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Simulated error"));

        assertThrows(RuntimeException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    void refreshToken_httpClientErrorException_throwsResponseStatusException() {
        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(httpEx);

        assertThrows(HttpClientErrorException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    void refreshToken_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenReturn("invalid-json");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al procesar la respuesta de renovación de Keycloak.", exception.getReason());
    }

    @Test
    void testRevokeRefreshToken() {
        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("revoke"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(String.class)
        )).thenReturn("");

        assertDoesNotThrow(() -> loginService.revokeRefreshToken(refreshTokenValue, realm, client));
        verify(keycloakOidcClient, times(1)).postRequest(anyString(), anyString(), any(), any(), eq(String.class));
    }

    @Test
    void revokeRefreshToken_realmNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", "unknownRealm", client));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    void revokeRefreshToken_clientSecretMissing() {
        clientSecrets.remove(client);
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", realm, client));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    void revokeRefreshToken_httpClientErrorException_throwsResponseStatusException() {
        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(httpEx);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("dummyRefresh", realm, client));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al revocar refresh token.", exception.getReason());
    }

    @Test
    void revokeRefreshToken_exceptionThrown() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Simulated error"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("dummyRefresh", realm, client));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al revocar refresh token.", exception.getReason());
    }
}
