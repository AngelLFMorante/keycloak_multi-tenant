package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.service.PasswordFlowService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

/**
 * Pruebas unitarias para {@link PasswordWebController} sin usar MockMvc.
 * <p>
 * Este enfoque prueba los métodos del controlador directamente,
 * aislando el código del framework Spring MVC. Es útil para probar la
 * lógica interna de los métodos, pero no para la integración completa del
 * controlador con la capa HTTP.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Pruebas directas para PasswordWebController")
class PasswordWebControllerTest {

    @Mock
    private PasswordFlowService flow;

    @InjectMocks
    private PasswordWebController controller;

    private final String REALM = "test-realm";
    private final String TOKEN = "some-secure-token";
    private final String PASSWORD = "new_Password123";

    @Test
    @DisplayName("Debería mostrar la página para establecer contraseña si el token es válido")
    void verify_validToken_shouldReturnSetPasswordView() {
        Model model = new ExtendedModelMap();

        String viewName = controller.verify(REALM, TOKEN, model);

        verify(flow).verifyEmail(REALM, TOKEN);

        assertEquals("set-password", viewName);

        assertEquals(REALM, model.getAttribute("realm"));
        assertEquals(TOKEN, model.getAttribute("token"));
    }

    @Test
    @DisplayName("Debería mostrar la página de error si el token no es válido")
    void verify_invalidToken_shouldReturnVerifyErrorView() {
        doThrow(new RuntimeException("Token inválido o expirado"))
                .when(flow).verifyEmail(REALM, TOKEN);

        Model model = new ExtendedModelMap();

        String viewName = controller.verify(REALM, TOKEN, model);

        assertEquals("verify-error", viewName);
        assertEquals("El enlace no es válido o ha expirado", model.getAttribute("error"));
    }

    @Test
    @DisplayName("Debería establecer la contraseña y redirigir a la página de éxito")
    void setPassword_validRequest_shouldReturnSuccessView() {
        Model model = new ExtendedModelMap();

        String viewName = controller.setPassword(REALM, TOKEN, PASSWORD, model);

        verify(flow).setPassword(REALM, TOKEN, PASSWORD);

        assertEquals("set-password-success", viewName);
        assertEquals("¡Contraseña definida! Espera activación del admin.", model.getAttribute("message"));
    }

    @Test
    @DisplayName("Debería manejar el error si no es posible establecer la contraseña")
    void setPassword_invalidRequest_shouldReturnSetPasswordViewWithError() {
        doThrow(new RuntimeException("No fue posible establecer la contraseña"))
                .when(flow).setPassword(REALM, TOKEN, PASSWORD);

        Model model = new ExtendedModelMap();

        String viewName = controller.setPassword(REALM, TOKEN, PASSWORD, model);

        assertEquals("set-password", viewName);
        assertEquals("No fue posible establecer la contraseña", model.getAttribute("error"));
        assertEquals(TOKEN, model.getAttribute("token"));
    }
}
