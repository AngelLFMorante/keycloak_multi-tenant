package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

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
    private RestTemplate restTemplate;

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
    private List<String> mockRealmRoles = List.of("app_users", "offline_access");
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
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://auth-server");

        when(restTemplate.postForEntity(
                any(String.class),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(new ResponseEntity<>(keycloakTokenResponse, HttpStatus.OK));

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

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakProperties, times(1)).getClientSecrets();
        verify(keycloakProperties, times(1)).getAuthServerUrl();
        verify(restTemplate, times(1)).postForEntity(any(String.class), any(HttpEntity.class), eq(String.class));
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
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        clientSecrets.remove("testClient");
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                loginService.authenticate(realm, "testClient", "user", "pass"));
        assertTrue(exception.getMessage().contains("secreto no encontrado"));
    }

    @Test
    void authenticate_httpClientErrorException_throwsResponseStatusException() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);

        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class))).thenThrow(httpEx);

        assertThrows(ResponseStatusException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    void authenticate_unexpectedException_throwsResponseStatusException() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);

        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Unexpected"));

        assertThrows(ResponseStatusException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    void authenticate_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>("invalid-json", HttpStatus.OK));

        assertThrows(ResponseStatusException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
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

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);

        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://auth-server");

        ResponseEntity<String> responseEntity = new ResponseEntity<>(tokenJson, HttpStatus.OK);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(responseEntity);

        LoginResponse response = loginService.refreshToken(oldRefreshToken, realm, client);

        assertNotNull(response);
        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());
    }

    @Test
    void refreshToken_realmNotFound() {
        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("token", "unknownRealm", "testClient"));
    }

    @Test
    void refreshToken_clientSecretMissing() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        assertThrows(IllegalArgumentException.class, () ->
                loginService.refreshToken("token", realm, null));
    }

    @Test
    void refreshToken_exceptionThrown() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);

        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Simulated error"));

        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    void refreshToken_httpClientErrorException_throwsResponseStatusException() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);

        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class))).thenThrow(httpEx);

        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    void refreshToken_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>("invalid-json", HttpStatus.OK));

        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    void testRevokeRefreshToken() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put("tenant1", "mapped-realm");
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);

        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put("client-app", "secret");
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://auth-server");

        assertDoesNotThrow(() -> loginService.revokeRefreshToken("refresh-token", "tenant1", "client-app"));
    }

    @Test
    void revokeRefreshToken_realmNotFound() {
        assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", "unknownRealm", "testClient"));
    }

    @Test
    void revokeRefreshToken_clientSecretMissing() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", realm, null));
    }

    @Test
    void revokeRefreshToken_exceptionThrown() {
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);

        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Simulated error"));

        assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("dummyRefresh", realm, client));
    }
}
