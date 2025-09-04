package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.RealmCreationRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRealmService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("RealmService Unit Tests")
class RealmServiceTest {

    @Mock
    private KeycloakRealmService keycloakRealmService;

    @InjectMocks
    private RealmService realmService;

    @Test
    @DisplayName("Debe delegar la creacion del realm a KeycloakRealmService")
    void createRealm_shouldDelegateToKeycloakRealmService() {
        String realmName = "nuevo-realm-de-prueba";
        RealmCreationRequest request = new RealmCreationRequest(realmName);

        realmService.createRealm(request);

        verify(keycloakRealmService, times(1)).createRealm(realmName);
    }

    @Test
    @DisplayName("Debe lanzar una excepcion si la creacion del realm falla en la capa inferior")
    void createRealm_shouldPropagateException_whenKeycloakServiceFails() {
        String realmName = "realm-existente";
        RealmCreationRequest request = new RealmCreationRequest(realmName);

        doThrow(ResponseStatusException.class)
                .when(keycloakRealmService)
                .createRealm(realmName);

        assertThrows(ResponseStatusException.class, () -> {
            realmService.createRealm(request);
        });

        verify(keycloakRealmService, times(1)).createRealm(realmName);
    }
}