package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.LoginResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para {@link WebIndexController} sin usar MockMvc.
 * <p>
 * Este enfoque prueba los métodos del controlador directamente,
 * aislando el código del framework Spring MVC.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Pruebas para WebIndexController")
class WebIndexControllerTest {

    @Mock
    private HttpSession session;

    @InjectMocks
    private WebIndexController controller;

    private final String REALM = "test-realm";
    private final String CLIENT = "test-client";
    private LoginResponse loginResponse;

    @BeforeEach
    void setUp() {
        loginResponse = new LoginResponse(
                "dummyAccessToken",
                "dummyIdToken",
                "dummyRefreshToken",
                3600,
                1800,
                REALM,
                CLIENT
        );
    }

    @Test
    @DisplayName("Debería mostrar la página de inicio con los datos de sesión si el usuario ha iniciado sesión")
    void index_userIsLoggedIn_shouldAddLoginDataToModel() {
        Model model = new ExtendedModelMap();
        when(session.getAttribute("loginResponse")).thenReturn(loginResponse);

        String viewName = controller.index(session, model);

        assertEquals("index", viewName);
        assertEquals(true, model.getAttribute("isLoggedIn"));
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
    }

    @Test
    @DisplayName("Debería mostrar la página de inicio con valores por defecto si el usuario no ha iniciado sesión")
    void index_userIsNotLoggedIn_shouldAddDefaultDataToModel() {
        Model model = new ExtendedModelMap();
        when(session.getAttribute("loginResponse")).thenReturn(null);

        String viewName = controller.index(session, model);

        assertEquals("index", viewName);
        assertEquals(false, model.getAttribute("isLoggedIn"));
        assertEquals("realm", model.getAttribute("tenantId"));
        assertEquals("my-client", model.getAttribute("clientId"));
    }

    @Test
    @DisplayName("Debería agregar solo los datos requeridos al modelo cuando el usuario ha iniciado sesión")
    void index_userIsLoggedIn_shouldOnlyAddRequiredDataToModel() {
        Model model = new ExtendedModelMap();
        loginResponse.setUsername("testuser");
        loginResponse.setEmail("testuser@example.com");
        loginResponse.setRoles(Collections.singletonList("USER"));
        when(session.getAttribute("loginResponse")).thenReturn(loginResponse);

        controller.index(session, model);

        assertEquals(true, model.containsAttribute("isLoggedIn"));
        assertEquals(true, model.containsAttribute("tenantId"));
        assertEquals(true, model.containsAttribute("clientId"));

        assertNull(model.getAttribute("username"), "El username no debe ser agregado al modelo por este controlador.");
        assertNull(model.getAttribute("email"), "El email no debe ser agregado al modelo por este controlador.");
        assertNull(model.getAttribute("roles"), "Los roles no deben ser agregados al modelo por este controlador.");
    }
}
