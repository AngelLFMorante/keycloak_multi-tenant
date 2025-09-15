package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para {@link WebAuthController} sin usar MockMvc.
 * <p>
 * Este enfoque prueba los métodos del controlador directamente,
 * aislando el código del framework Spring MVC.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Pruebas para WebAuthController")
class WebAuthControllerTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private SecurityContextRepository securityContextRepository;

    @Mock
    private LoginService loginService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @InjectMocks
    private WebAuthController webAuthController;

    private final String REALM = "test-realm";
    private final String CLIENT = "test-client";
    private final String USERNAME = "user";
    private final String PASSWORD = "password";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Debería mostrar la página de login sin error")
    void showLoginPage_noError_shouldReturnLoginView() {
        Model model = new ExtendedModelMap();

        String viewName = webAuthController.showLoginPage(REALM, CLIENT, null, model);

        assertEquals("login", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
    }

    @Test
    @DisplayName("Debería mostrar la página de login con mensaje de error")
    void showLoginPage_withError_shouldReturnLoginViewAndError() {
        Model model = new ExtendedModelMap();
        String error = "Credenciales inválidas";

        String viewName = webAuthController.showLoginPage(REALM, CLIENT, error, model);

        assertEquals("login", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertEquals(error, model.getAttribute("error"));
    }

    @Test
    @DisplayName("Debería procesar el login con éxito y redirigir a la página de inicio")
    void processLogin_success_shouldRedirectToHome() {
        Model model = new ExtendedModelMap();
        LoginResponse loginResponse = mock(LoginResponse.class);
        when(loginResponse.getPreferredUsername()).thenReturn(USERNAME);
        when(loginResponse.getRoles()).thenReturn(List.of("ROLE_USER"));

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                USERNAME, SecurityConfig.DUMMY_PASSWORD, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        when(loginService.authenticate(REALM, CLIENT, USERNAME, PASSWORD)).thenReturn(loginResponse);
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);
        when(request.getSession(true)).thenReturn(session);

        String viewName = webAuthController.processLogin(REALM, CLIENT, USERNAME, PASSWORD, request, response, model);

        assertEquals("redirect:/test-realm/home", viewName);
        verify(session).setAttribute("realm", REALM);
        verify(session).setAttribute("client", CLIENT);
        verify(session).setAttribute("loginResponse", loginResponse);
        verify(securityContextRepository).saveContext(any(SecurityContext.class), eq(request), eq(response));
    }

    @Test
    @DisplayName("Debería procesar el login y mostrar la página de login con error si falla")
    void processLogin_failure_shouldReturnLoginViewWithError() {
        Model model = new ExtendedModelMap();
        when(loginService.authenticate(REALM, CLIENT, USERNAME, PASSWORD))
                .thenThrow(new RuntimeException("Credenciales inválidas"));

        String viewName = webAuthController.processLogin(REALM, CLIENT, USERNAME, PASSWORD, request, response, model);

        assertEquals("login", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertEquals("Usuario o contraseña incorrectos", model.getAttribute("error"));
    }

    @Test
    @DisplayName("Debería mostrar la página de inicio con los datos de LoginResponse")
    void home_withLoginResponse_shouldReturnHomeViewAndPopulateModel() {
        Model model = new ExtendedModelMap();
        LoginResponse loginResponse = mock(LoginResponse.class);
        when(session.getAttribute("loginResponse")).thenReturn(loginResponse);
        when(loginResponse.getRealm()).thenReturn(REALM);
        when(loginResponse.getUsername()).thenReturn(USERNAME);
        when(loginResponse.getEmail()).thenReturn("user@email.com");
        when(loginResponse.getFullName()).thenReturn("Test User");
        when(loginResponse.getRoles()).thenReturn(Collections.singletonList("admin"));
        when(loginResponse.getClient()).thenReturn(CLIENT);

        String viewName = webAuthController.home(REALM, model, session);

        assertEquals("home", viewName);
        assertEquals(REALM, model.getAttribute("realmName"));
        assertEquals(USERNAME, model.getAttribute("username"));
        assertEquals("user@email.com", model.getAttribute("email"));
        assertEquals("Test User", model.getAttribute("fullName"));
        assertEquals(Collections.singletonList("admin"), model.getAttribute("roles"));
    }

    @Test
    @DisplayName("Debería mostrar la página de inicio con el nombre de usuario de SecurityContextHolder")
    void home_noLoginResponse_shouldReturnHomeViewAndPopulateModel() {
        Model model = new ExtendedModelMap();
        Authentication authentication = new UsernamePasswordAuthenticationToken(USERNAME, "password");
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);
        when(session.getAttribute("loginResponse")).thenReturn(null);

        String viewName = webAuthController.home(REALM, model, session);

        assertEquals("home", viewName);
        assertEquals(USERNAME, model.getAttribute("username"));
    }

    @Test
    @DisplayName("Debería cerrar la sesión y redirigir a la página de login")
    void logout_success_shouldInvalidateSessionAndRedirect() {
        LoginResponse loginResponse = mock(LoginResponse.class);
        when(loginResponse.getRefreshToken()).thenReturn("fake-refresh-token");
        when(session.getAttribute("realm")).thenReturn(REALM);
        when(session.getAttribute("client")).thenReturn(CLIENT);
        when(session.getAttribute("loginResponse")).thenReturn(loginResponse);
        when(request.getSession(false)).thenReturn(session);

        String viewName = webAuthController.logout(request);

        assertEquals("redirect:/test-realm/test-client/login", viewName);
        verify(loginService).revokeRefreshToken("fake-refresh-token", REALM, CLIENT);
        verify(session).invalidate();
    }

    @Test
    @DisplayName("Debería redirigir a la raíz si no hay sesión para cerrar")
    void logout_noSession_shouldRedirectToRoot() {
        when(request.getSession(false)).thenReturn(null);

        String viewName = webAuthController.logout(request);

        assertEquals("redirect:/", viewName);
        verify(session, never()).invalidate();
    }
}
