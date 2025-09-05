package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for ClientService")
class ClientServiceTest {

    @Mock
    private KeycloakClientService keycloakClientService;

    @InjectMocks
    private ClientService clientService;

    private ClientCreationRequest request;
    private final String realmName = "test-realm";
    private final String clientName = "test-client";
    private final String clientSecret = "secret-123";

    @BeforeEach
    void setUp() {
        request = new ClientCreationRequest(realmName, clientName);
    }

    @Test
    @DisplayName("should delegate client creation to KeycloakClientService and return secret")
    void createClient_shouldReturnClientSecret() {
        when(keycloakClientService.createClient(realmName, clientName)).thenReturn(clientSecret);

        String returnedSecret = clientService.createClient(request);

        assertEquals(clientSecret, returnedSecret);
        verify(keycloakClientService, times(1)).createClient(realmName, clientName);
    }
}
