package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakOidcClient;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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

/**
 * Clase de test para {@link LoginService}.
 */
class LoginServiceTest {

    @Mock
    private KeycloakOidcClient keycloakOidcClient;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private KeycloakConfigService keycloakConfigService;

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
    private String mockAccessToken;
    private String mockIdToken;
    private String keycloakTokenResponse;
    private KeyPair keyPair;


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

        keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

        mockAccessToken = Jwts.builder()
                .setSubject("54321")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 300000))
                .claim("email", "test@example.com")
                .claim("name", "Test User")
                .claim("preferred_username", username)
                .claim("realm_access", Map.of("roles", List.of("app_users", "offline_access")))
                .claim("resource_access", Map.of(client, Map.of("roles", List.of("user_app"))))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

        mockIdToken = Jwts.builder()
                .setSubject("54321")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 300000))
                .claim("email", "test@example.com")
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

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

    @Test
    @DisplayName("Debería autenticar al usuario y decodificar el token correctamente")
    void testAuthenticateSuccess() {
        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("token"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(String.class)
        )).thenReturn(keycloakTokenResponse);

        when(keycloakConfigService.getRealmPublicKey(realm)).thenReturn(keyPair.getPublic());

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
        assertEquals("test@example.com", response.getEmail());
        assertEquals("Test User", response.getFullName());

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakProperties, times(1)).getClientSecrets();
        verify(keycloakOidcClient, times(1)).postRequest(anyString(), anyString(), any(), any(), eq(String.class));
        verify(keycloakConfigService, times(1)).getRealmPublicKey(realm);
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el tenant no es reconocido")
    void testAuthenticateTenantNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> loginService.authenticate("unknown", "client", "user", "pass"));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
    }

    @Test
    @DisplayName("Debería lanzar IllegalArgumentException si el client secret no se encuentra")
    void authenticate_clientSecretIsNull_throwsIllegalArgumentException() {
        clientSecrets.remove(client);
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
        assertTrue(exception.getMessage().contains("secreto no encontrado"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException cuando el cliente HTTP arroja un error")
    void authenticate_httpClientErrorException_throwsResponseStatusException() {
        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(httpEx);

        assertThrows(HttpClientErrorException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    @DisplayName("Debería lanzar una excepción para errores inesperados durante la autenticación")
    void authenticate_unexpectedException_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Unexpected"));

        assertThrows(RuntimeException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException para respuestas de token inválidas")
    void authenticate_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenReturn("invalid-json");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.authenticate(realm, client, "user", "pass"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al procesar la respuesta de Keycloak.", exception.getReason());
    }

    @Test
    @DisplayName("Debería renovar el token correctamente")
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
    @DisplayName("Debería lanzar ResponseStatusException si el realm no es encontrado al refrescar el token")
    void refreshToken_realmNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("token", "unknownRealm", "testClient"));
    }

    @Test
    @DisplayName("Debería lanzar IllegalArgumentException si el client secret falta al refrescar el token")
    void refreshToken_clientSecretMissing() {
        clientSecrets.remove(client);
        assertThrows(IllegalArgumentException.class, () ->
                loginService.refreshToken("token", realm, client));
    }

    @Test
    @DisplayName("Debería lanzar una excepción si ocurre un error inesperado al refrescar el token")
    void refreshToken_exceptionThrown() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Simulated error"));

        assertThrows(RuntimeException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException cuando el cliente HTTP arroja un error al refrescar el token")
    void refreshToken_httpClientErrorException_throwsResponseStatusException() {
        HttpClientErrorException httpEx = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, StandardCharsets.UTF_8);
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenThrow(httpEx);

        assertThrows(HttpClientErrorException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException para respuestas de token inválidas al refrescar")
    void refreshToken_invalidTokenResponse_throwsResponseStatusException() {
        when(keycloakOidcClient.postRequest(anyString(), anyString(), any(), any(), eq(String.class)))
                .thenReturn("invalid-json");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.refreshToken("dummyRefresh", realm, client));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al procesar la respuesta de renovación de Keycloak.", exception.getReason());
    }

    @Test
    @DisplayName("Debería revocar el token de refresco correctamente")
    void testRevokeRefreshToken() {
        String fullRefreshToken = "header.payload.signature";

        String expectedTruncatedToken = "header.payload";

        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("logout"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(String.class)
        )).thenReturn("");

        assertDoesNotThrow(() -> loginService.revokeRefreshToken(fullRefreshToken, realm, client));

        MultiValueMap<String, String> expectedParams = new LinkedMultiValueMap<>();
        expectedParams.add("client_id", client);
        expectedParams.add("client_secret", clientSecret);
        expectedParams.add("token", expectedTruncatedToken);
        expectedParams.add("token_type_hint", "refresh_token");

        verify(keycloakOidcClient, times(1)).postRequest(
                eq(keycloakRealm),
                eq("logout"),
                eq(expectedParams),
                any(HttpHeaders.class),
                eq(String.class)
        );
    }


    @Test
    @DisplayName("Debería lanzar una excepción si el realm no se encuentra al revocar el token")
    void revokeRefreshToken_realmNotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", "unknownRealm", client));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    @DisplayName("Debería lanzar una excepción si el client secret falta al revocar el token")
    void revokeRefreshToken_clientSecretMissing() {
        clientSecrets.remove(client);
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginService.revokeRefreshToken("token", realm, client));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }
}
