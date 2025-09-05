package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.ClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class ClientControllerTest {

    @Mock
    private ClientService clientService;

    @InjectMocks
    private ClientController clientController;

    private ClientCreationRequest clientCreationRequest;
    private final String clientName = "test-client";
    private final String realmName = "test-realm";
    private final String clientSecret = "mock-secret-value";

    @BeforeEach
    void setUp() {
        clientCreationRequest = new ClientCreationRequest(clientName, realmName);
    }

    @Test
    void testCreateClient_Success() {
        when(clientService.createClient(clientCreationRequest)).thenReturn(clientSecret);

        ResponseEntity<String> responseEntity = clientController.createClient(clientCreationRequest);

        assertEquals(HttpStatus.CREATED, responseEntity.getStatusCode());

        String expectedMessage = String.format("Cliente '%s' creado exitosamente. Client Secret: '%s'", realmName, clientSecret);
        assertEquals(expectedMessage, responseEntity.getBody());

        verify(clientService, times(1)).createClient(clientCreationRequest);
    }
}
