package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for KeycloakClientService")
class KeycloakClientServiceTest {

    @Mock
    private KeycloakAdminService keycloakAdminService;

    @Mock
    private RealmResource realmResource;

    @Mock
    private ClientsResource clientsResource;

    @Mock
    private ClientResource clientResource;

    @Mock
    private Response response;

    @InjectMocks
    private KeycloakClientService keycloakClientService;

    private String realmName;
    private String clientId;
    private String clientSecretValue;
    private String internalClientId;

    @BeforeEach
    void setUp() {
        realmName = "test-realm";
        clientId = "test-client";
        clientSecretValue = "test-client-secret";
        internalClientId = "a4b5c6d7";

        when(keycloakAdminService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.clients()).thenReturn(clientsResource);
    }

    @Test
    @DisplayName("should create a client and return its secret successfully")
    void createClient_shouldReturnSecret_whenSuccessful() {
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/realms/test-realm/clients/" + internalClientId));
        when(clientsResource.create(any(ClientRepresentation.class))).thenReturn(response);

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType("secret");
        credentialRepresentation.setValue(clientSecretValue);

        when(clientsResource.get(internalClientId)).thenReturn(clientResource);
        when(clientResource.getSecret()).thenReturn(credentialRepresentation);

        String returnedSecret = keycloakClientService.createClient(realmName, clientId);

        assertEquals(clientSecretValue, returnedSecret);

        verify(keycloakAdminService, times(2)).getRealmResource(realmName);
        verify(clientsResource, times(1)).create(any(ClientRepresentation.class));
        verify(clientsResource, times(1)).get(internalClientId);
        verify(clientResource, times(1)).getSecret();
    }

    @Test
    @DisplayName("should throw ClientErrorException when client creation fails")
    void createClient_shouldThrowException_whenCreationFails() {
        when(response.getStatus()).thenReturn(409);
        when(clientsResource.create(any(ClientRepresentation.class))).thenReturn(response);

        ClientErrorException exception = assertThrows(ClientErrorException.class, () ->
                keycloakClientService.createClient(realmName, clientId)
        );

        assertEquals(409, exception.getResponse().getStatus());
    }

}
