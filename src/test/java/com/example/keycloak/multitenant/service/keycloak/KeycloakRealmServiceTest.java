package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("KeycloakRealmService Unit Tests")
class KeycloakRealmServiceTest {

    @Mock
    private KeycloakAdminService utilsAdminService;

    @Mock
    private RealmsResource realmsResource;

    @InjectMocks
    private KeycloakRealmService keycloakRealmService;

    private static final String REALM_NAME = "test-realm";

    @Test
    @DisplayName("Debe crear un nuevo realm cuando no existe previamente")
    void createRealm_shouldCreateRealm_whenItDoesNotExist() {
        when(utilsAdminService.realms()).thenReturn(realmsResource);
        when(utilsAdminService.getRealm(REALM_NAME)).thenReturn(null);

        keycloakRealmService.createRealm(REALM_NAME);

        verify(utilsAdminService, times(1)).getRealm(REALM_NAME);
        verify(realmsResource, times(1)).create(any(RealmRepresentation.class));
    }

    @Test
    @DisplayName("Debe lanzar una excepcion de conflicto si el realm ya existe")
    void createRealm_shouldThrowException_whenRealmAlreadyExists() {
        RealmRepresentation mockRealm = new RealmRepresentation();
        mockRealm.setRealm(REALM_NAME);

        when(utilsAdminService.getRealm(REALM_NAME)).thenReturn(mockRealm);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () -> {
            keycloakRealmService.createRealm(REALM_NAME);
        });

        assertEquals(HttpStatus.CONFLICT, thrown.getStatusCode(), "El código de estado debe ser CONFLICT");
        assertEquals("El realm ya existe.", thrown.getReason(), "El mensaje de la excepción debe ser 'El realm ya existe.'");

        verify(realmsResource, never()).create(any(RealmRepresentation.class));
        verify(utilsAdminService, times(1)).getRealm(REALM_NAME);
    }
}