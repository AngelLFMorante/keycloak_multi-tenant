package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

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
    @Mock
    private HttpSession session;
    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private LoginController loginController;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setContext(securityContext);
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
    @DisplayName("Debería retornar el realm del tenant para GET /realm/login")
    void redirectToTenantLogin_shouldReturnTenantRealm() {
        String realm = "plexus";
        String keycloakRealm = "plexus-realm";
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(realm, keycloakRealm);

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);

        ResponseEntity<Map<String, Object>> responseEntity = loginController.redirectToTenantLogin(realm);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(realm, responseEntity.getBody().get("realm"));
        assertEquals(keycloakRealm, responseEntity.getBody().get("keycloakRealm"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el realm no está mapeado para GET /realm/login")
    void redirectToTenantLogin_shouldThrowExceptionForUnmappedRealm() {
        String realm = "unknown";
        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            loginController.redirectToTenantLogin(realm);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Tenant " + realm + " no reconocido."));
    }

    @Test
    @DisplayName("Debería procesar el login exitosamente y retornar tokens y roles")
    void doLogin_shouldProcessLoginSuccessfully() throws Exception {
        String realm = "plexus";
        String client = "mi-app-plexus";
        String username = "testuser";
        String password = "testpassword";
        String keycloakRealm = "plexus-realm";
        String clientSecret = "mock-client-secret";
        String refreshTokenValue = "some-refresh-token";

        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(realm, keycloakRealm);

        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put(client, clientSecret);

        String authServerUrl = "http://localhost:8080";
        String issuerUrl = authServerUrl + "/realms/" + keycloakRealm;

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);

        List<String> mockRealmRoles = List.of("app_users", "offline_access");
        Map<String, List<String>> mockClientRoles = new HashMap<>();
        mockClientRoles.put(client, List.of("user_app"));

        String mockAccessToken = createMockJwt(username, "test@example.com", "Test User", mockRealmRoles, mockClientRoles, issuerUrl);
        String mockIdToken = createMockJwt(username, "test@example.com", "Test User", Collections.emptyList(), Collections.emptyMap(), issuerUrl);

        String keycloakTokenResponse = "{" +
                "\"access_token\":\"" + mockAccessToken + "\"," +
                "\"id_token\":\"" + mockIdToken + "\"," +
                "\"refresh_token\":\"" + refreshTokenValue + "\"," +
                "\"expires_in\":300," +
                "\"refresh_expires_in\":1800" +
                "}";

        when(restTemplate.postForEntity(
                any(String.class),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(new ResponseEntity<>(keycloakTokenResponse, HttpStatus.OK));

        List<SimpleGrantedAuthority> expectedAuthorities = new java.util.ArrayList<>();
        mockRealmRoles.forEach(role -> expectedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
        mockClientRoles.get(client).forEach(role -> expectedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));

        Authentication auth = new UsernamePasswordAuthenticationToken(username, SecurityConfig.DUMMY_PASSWORD, expectedAuthorities);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);

        doAnswer(invocation -> {
            Authentication authentication = invocation.getArgument(0);
            when(securityContext.getAuthentication()).thenReturn(authentication);
            return null;
        }).when(securityContext).setAuthentication(any(Authentication.class));

        when(request.getSession(true)).thenReturn(session);

        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(realm, client, username, password, request, response);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

        Map<String, Object> responseBody = responseEntity.getBody();
        assertNotNull(responseBody);
        assertEquals("Login successful", responseBody.get("message"));
        assertEquals("testuser", responseBody.get("username"));
        assertEquals("test@example.com", responseBody.get("email"));
        assertEquals("Test User", responseBody.get("fullName"));

        List<String> actualRoles = (List<String>) responseBody.get("roles");
        assertNotNull(actualRoles);
        assertEquals(expectedAuthorities.size(), actualRoles.size());
        assertTrue(actualRoles.contains("ROLE_APP_USERS"));
        assertTrue(actualRoles.contains("ROLE_OFFLINE_ACCESS"));
        assertTrue(actualRoles.contains("ROLE_USER_APP"));

        assertNotNull(responseBody.get("accessToken"));
        assertNotNull(responseBody.get("idToken"));
        assertNotNull(responseBody.get("refreshToken"));
        assertEquals(300L, responseBody.get("expiresIn"));
        assertEquals(1800L, responseBody.get("refreshExpiresIn"));
        assertEquals(realm, responseBody.get("realm"));
        assertEquals(client, responseBody.get("client"));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakProperties, times(1)).getClientSecrets();
        verify(keycloakProperties, times(1)).getAuthServerUrl();
        verify(restTemplate, times(1)).postForEntity(any(String.class), any(HttpEntity.class), eq(String.class));
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, times(1)).saveContext(eq(securityContext), eq(request), eq(response));
        verify(securityContext, times(1)).setAuthentication(any(Authentication.class));

        verify(request, times(1)).getSession(true);
        verify(session, times(1)).setAttribute("refreshToken", refreshTokenValue);
        verify(session, times(1)).setAttribute("realm", realm);
        verify(session, times(1)).setAttribute("clientUsed", client);
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el tenant no está mapeado durante el login")
    void doLogin_shouldThrowExceptionForUnmappedRealm() {
        String realm = "unknown";
        String client = "mi-app-plexus";
        String username = "user";
        String password = "password";

        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            loginController.doLogin(realm, client, username, password, request, response);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Tenant " + realm + " no reconocido."));
    }

    @Test
    @DisplayName("Debería lanzar IllegalArgumentException si el secreto del cliente no está configurado")
    void doLogin_shouldThrowExceptionForMissingClientSecret() {
        String realm = "plexus";
        String client = "unknown-client";
        String username = "user";
        String password = "password";

        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(realm, "plexus-realm");

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakProperties.getClientSecrets()).thenReturn(Collections.emptyMap());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            loginController.doLogin(realm, client, username, password, request, response);
        });

        assertTrue(exception.getMessage().contains("Client ID configurado pero secreto no encontrado para: " + client));
    }
}
