package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.ClientService;
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
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para {@link WebClientController} sin usar MockMvc.
 * <p>
 * Este enfoque prueba los métodos del controlador directamente,
 * aislando el código del framework Spring MVC.
 *
 * @author Angel Fm
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Pruebas para WebClientController")
public class WebClientControllerTest {

    @Mock
    private ClientService clientService;

    @InjectMocks
    private WebClientController controller;

    private final String REALM = "test-realm";
    private final String CLIENT_NAME = "test-client";
    private final String CLIENT_SECRET = "test-client-secret";

    @Test
    @DisplayName("Debería mostrar el formulario de creación de cliente")
    void showCreateClientForm_shouldReturnCreateClientView() {
        Model model = new ExtendedModelMap();

        String viewName = controller.showCreateClientForm(REALM, model);

        assertEquals("create-client", viewName);
        assertEquals(REALM, model.getAttribute("realm"));
    }

    @Test
    @DisplayName("Debería procesar la creación de un cliente con éxito y devolver la vista con el secreto")
    void createClient_success_shouldReturnCreateClientViewWithSecret() {
        Model model = new ExtendedModelMap();
        when(clientService.createClient(new ClientCreationRequest(REALM, CLIENT_NAME)))
                .thenReturn(CLIENT_SECRET);

        String viewName = controller.createClient(REALM, CLIENT_NAME, model);

        assertEquals("create-client", viewName);
        assertEquals("¡Cliente creado exitosamente!", model.getAttribute("message"));
        assertEquals(REALM, model.getAttribute("realm"));
        assertEquals(CLIENT_SECRET, model.getAttribute("clientSecret"));
    }

    @Test
    @DisplayName("Debería manejar el error si falla la creación de un cliente")
    void createClient_failure_shouldReturnCreateClientViewWithError() {
        Model model = new ExtendedModelMap();
        String errorMessage = "Error de prueba al crear el cliente.";
        doThrow(new RuntimeException(errorMessage))
                .when(clientService).createClient(new ClientCreationRequest(REALM, CLIENT_NAME));

        String viewName = controller.createClient(REALM, CLIENT_NAME, model);

        assertEquals("create-client", viewName);
        assertEquals("Error al crear el cliente: " + errorMessage, model.getAttribute("error"));
        assertEquals(REALM, model.getAttribute("realm"));
    }
}
