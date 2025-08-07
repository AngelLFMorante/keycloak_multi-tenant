package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.AuthResponse;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.AuthService;
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
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
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
    private AuthService authService;

    private KeycloakProperties keycloakProperties;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private HttpSession session;
    @Mock
    private SecurityContext securityContext;

    private LoginController loginController;

    private String realm;
    private String keycloakRealm;
    private String clientSecret;
    private String client;
    private String username;
    private String password;
    private Map<String, String> realmMapping;
    private Map<String, String> clientSecrets;
    private String authServerUrl;
    private KeycloakProperties.Admin admin;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setContext(securityContext);
        keycloakProperties = new KeycloakProperties();
        loginController = new LoginController(
                authenticationManager,
                securityContextRepository,
                authService,
                keycloakProperties
        );

        realm = "plexus";
        keycloakRealm = "plexus-realm";
        clientSecret = "mock-client-secret";
        client = "mi-app-plexus";
        username = "testuser";
        password = "testpassword";
        realmMapping = new HashMap<>();
        realmMapping.put(realm, keycloakRealm);
        clientSecrets = new HashMap<>();
        clientSecrets.put(client, clientSecret);
        authServerUrl = "http://localhost:8080";
        admin = new KeycloakProperties.Admin();
        admin.setRealm(realm);
        admin.setClientId(client);
        admin.setUsername(username);
        admin.setPassword(password);

        keycloakProperties.setRealmMapping(realmMapping);
        keycloakProperties.setClientSecrets(clientSecrets);
        keycloakProperties.setAuthServerUrl(authServerUrl);
        keycloakProperties.setAdmin(admin);
    }

    @Test
    @DisplayName("Debería retornar el realm del tenant para GET /{realm}/login")
    void redirectToTenantLogin_shouldReturnTenantRealm() {
        ResponseEntity<Map<String, Object>> responseEntity = loginController.redirectToTenantLogin(realm);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(realm, responseEntity.getBody().get("realm"));
        assertEquals(keycloakRealm, responseEntity.getBody().get("keycloakRealm"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el realm no está mapeado para GET /{realm}/login")
    void redirectToTenantLogin_shouldThrowExceptionForUnmappedRealm() {
        keycloakProperties.setRealmMapping(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            loginController.redirectToTenantLogin("unknown");
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Tenant unknown no reconocido."));
    }

    @Test
    @DisplayName("Debería procesar el login exitosamente y retornar tokens y roles")
    void doLogin_shouldProcessLoginSuccessfully() throws Exception {
        AuthResponse mockAuthResponse = new AuthResponse(
                "mockAccessToken", "mockIdToken", "mockRefreshToken",
                300L, 1800L, username, "test@example.com", "Test User",
                List.of("ROLE_APP_USERS", "ROLE_OFFLINE_ACCESS", "ROLE_USER_APP"),
                realm, client, username
        );
        when(authService.authenticate(eq(realm), eq(client), eq(username), eq(password))).thenReturn(mockAuthResponse);

        List<SimpleGrantedAuthority> expectedAuthorities = List.of(
                new SimpleGrantedAuthority("ROLE_APP_USERS"),
                new SimpleGrantedAuthority("ROLE_OFFLINE_ACCESS"),
                new SimpleGrantedAuthority("ROLE_USER_APP")
        );
        Authentication auth = new UsernamePasswordAuthenticationToken(username, SecurityConfig.DUMMY_PASSWORD, expectedAuthorities);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);
        doAnswer(invocation -> {
            return null;
        }).when(securityContext).setAuthentication(any(Authentication.class));
        when(request.getSession(true)).thenReturn(session);

        ResponseEntity<Map<String, Object>> responseEntity = loginController.doLogin(realm, client, username, password, request, response);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        Map<String, Object> responseBody = responseEntity.getBody();
        assertNotNull(responseBody);
        assertEquals("Login successful", responseBody.get("message"));

        List<String> actualRoles = (List<String>) responseBody.get("roles");
        assertNotNull(actualRoles);
        assertTrue(actualRoles.contains("ROLE_APP_USERS"));

        verify(authService, times(1)).authenticate(eq(realm), eq(client), eq(username), eq(password));
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(securityContextRepository, times(1)).saveContext(eq(securityContext), eq(request), eq(response));
        verify(session, times(1)).setAttribute("realm", realm);
        verify(session, times(1)).setAttribute("client", client);
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el login falla en el AuthService")
    void doLogin_shouldThrowExceptionIfAuthServiceFails() {
        when(authService.authenticate(any(), any(), any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.doLogin(realm, client, username, password, request, response)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        verify(authenticationManager, never()).authenticate(any());
        verify(securityContextRepository, never()).saveContext(any(), any(), any());
    }

    @Test
    @DisplayName("Debería renovar el token exitosamente")
    void refreshToken_shouldSucceed() {
        String refreshTokenValue = "mockRefreshToken";
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("realm")).thenReturn(realm);
        when(session.getAttribute("client")).thenReturn(client);

        AuthResponse mockAuthResponse = new AuthResponse(
                "newAccessToken", "newIdToken", "newRefreshToken",
                300L, 1800L, realm, client
        );
        when(authService.refreshToken(eq(refreshTokenValue), eq(realm), eq(client))).thenReturn(mockAuthResponse);

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshTokenValue);
        ResponseEntity<Map<String, Object>> responseEntity = loginController.refreshToken(request, refreshTokenRequest);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals("Token refreshed successfully", responseEntity.getBody().get("message"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si es null refreshToken")
    void refreshToken_shouldThrowExceptionForNoRefreshToken() {
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(null);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.refreshToken(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si no hay sesion activa en refreshToken")
    void refreshToken_shouldThrowExceptionForNoActiveSession() {
        when(request.getSession(false)).thenReturn(null);
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("token");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.refreshToken(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si faltan datos en la sesion en refreshToken")
    void refreshToken_shouldThrowExceptionForMissingSessionData() {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("realm")).thenReturn(null);
        when(session.getAttribute("client")).thenReturn(client);
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("token");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.refreshToken(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Faltan datos de sesion"));
    }

    @Test
    @DisplayName("Debería realizar el logout exitosamente")
    void logout_shouldSucceed() {
        String refreshTokenValue = "mockRefreshToken";
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("realm")).thenReturn(realm);
        when(session.getAttribute("client")).thenReturn(client);
        doNothing().when(authService).revokeRefreshToken(any(), any(), any());

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshTokenValue);
        ResponseEntity<Map<String, Object>> responseEntity = loginController.logout(request, refreshTokenRequest);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals("Logout exitoso. Token revocado.", responseEntity.getBody().get("message"));

        verify(authService, times(1)).revokeRefreshToken(eq(refreshTokenValue), eq(realm), eq(client));
        verify(session, times(1)).invalidate();
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el refresh token es nulo en logout")
    void logout_shouldThrowExceptionForMissingToken() {
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(null);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.logout(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("refresh_token' es obligatorio."));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si no hay sesion activa en logout")
    void logout_shouldThrowExceptionForNoActiveSession() {
        when(request.getSession(false)).thenReturn(null);
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("token");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.logout(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si faltan datos en la sesion en logout")
    void logout_shouldThrowExceptionForMissingSessionData() {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("realm")).thenReturn(null);
        when(session.getAttribute("client")).thenReturn(client);
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("token");

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                loginController.logout(request, refreshTokenRequest)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Faltan datos de sesion"));
    }
}
