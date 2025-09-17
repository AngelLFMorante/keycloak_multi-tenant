package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.service.UserService;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para {@link WebRegisterController} sin usar MockMvc.
 * <p>
 * Este enfoque prueba los métodos del controlador directamente,
 * aislando el código del framework Spring MVC.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Pruebas para WebRegisterController")
class WebRegisterControllerTest {

    @Mock
    private UserService userService;

    @Mock
    private BindingResult bindingResult;

    @InjectMocks
    private WebRegisterController controller;

    private final String REALM = "test-realm";
    private final String CLIENT = "test-client";
    private Model model;

    @BeforeEach
    void setUp() {
        model = new ExtendedModelMap();
    }

    @Test
    @DisplayName("Debería mostrar el formulario de registro y añadir los atributos correctos al modelo")
    void showRegisterForm_shouldReturnRegisterViewAndAddAttributes() {
        String viewName = controller.showRegisterForm(REALM, CLIENT, model);

        assertEquals("register", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertNotNull(model.getAttribute("registerRequest"));
        assertEquals(UserRequest.class, model.getAttribute("registerRequest").getClass());
    }

    @Test
    @DisplayName("Debería procesar el registro exitosamente y añadir el mensaje de éxito")
    void processRegister_validRequest_shouldReturnRegisterViewWithSuccessMessage() throws Exception {
        UserRequest userRequest = new UserRequest("user", "test@example.com", "John", "Doe", null);
        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("message", "Usuario registrado. Esperando aprobacion de administrador.");
        when(bindingResult.hasErrors()).thenReturn(false);
        when(userService.registerUser(REALM, userRequest)).thenReturn(mockResponse);

        String viewName = controller.processRegister(REALM, CLIENT, userRequest, bindingResult, model);

        assertEquals("register", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertEquals("Usuario registrado. Revisa tu email para activar la cuenta y definir contraseña.", model.getAttribute("message"));
        verify(userService, times(1)).registerUser(REALM, userRequest);
    }

    @Test
    @DisplayName("Debería retornar el formulario con errores si la validación falla")
    void processRegister_validationError_shouldReturnRegisterView() throws Exception {
        UserRequest userRequest = new UserRequest("user", "test@example.com", "John", "Doe", null);
        when(bindingResult.hasErrors()).thenReturn(true);

        String viewName = controller.processRegister(REALM, CLIENT, userRequest, bindingResult, model);

        assertEquals("register", viewName);
        verify(userService, never()).registerUser(anyString(), any(UserRequest.class));
    }

    @Test
    @DisplayName("Debería manejar la excepción de email ya registrado y añadir un mensaje de error")
    void processRegister_emailAlreadyExists_shouldReturnRegisterViewWithError() throws Exception {
        UserRequest userRequest = new UserRequest("user", "test@example.com", "John", "Doe", null);
        when(bindingResult.hasErrors()).thenReturn(false);
        when(userService.registerUser(REALM, userRequest)).thenThrow(new IllegalArgumentException("El email ya está registrado."));

        String viewName = controller.processRegister(REALM, CLIENT, userRequest, bindingResult, model);

        assertEquals("register", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertEquals("Ocurrió un error inesperado.", model.getAttribute("error"));
        verify(userService, times(1)).registerUser(REALM, userRequest);
    }

    @Test
    @DisplayName("Debería manejar otras excepciones y añadir un mensaje de error al modelo")
    void processRegister_exception_shouldReturnRegisterViewWithError() throws Exception {
        UserRequest userRequest = new UserRequest("user", "test@example.com", "John", "Doe", null);
        when(bindingResult.hasErrors()).thenReturn(false);
        when(userService.registerUser(REALM, userRequest)).thenThrow(new RuntimeException("Test exception"));

        String viewName = controller.processRegister(REALM, CLIENT, userRequest, bindingResult, model);

        assertEquals("register", viewName);
        assertEquals(REALM, model.getAttribute("tenantId"));
        assertEquals(CLIENT, model.getAttribute("clientId"));
        assertEquals("Ocurrió un error inesperado.", model.getAttribute("error"));
    }
}
