package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.controller.api.RealmController;
import com.example.keycloak.multitenant.model.RealmCreationRequest;
import com.example.keycloak.multitenant.service.RealmService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("RealmController Unit Tests without MVC")
class RealmControllerTest {

    @Mock
    private RealmService realmService;

    @InjectMocks
    private RealmController realmController;

    @Test
    @DisplayName("should create a new realm and return 201 Created")
    void createRealm_shouldReturn201Created_whenSuccessful() {
        String realmName = "new-test-realm";
        RealmCreationRequest request = new RealmCreationRequest(realmName);
        doNothing().when(realmService).createRealm(request);

        ResponseEntity<String> response = realmController.createRealm(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode(), "El código de estado debe ser 201 CREATED");
        assertEquals("Realm 'new-test-realm' creado exitosamente.", response.getBody(), "El mensaje de éxito debe ser correcto");

        verify(realmService, times(1)).createRealm(request);
    }

    @Test
    @DisplayName("should handle realm already exists and throw a 409 Conflict")
    void createRealm_shouldThrow409Conflict_whenRealmAlreadyExists() {
        String realmName = "existing-realm";
        RealmCreationRequest request = new RealmCreationRequest(realmName);
        doThrow(new ResponseStatusException(HttpStatus.CONFLICT, "El realm ya existe."))
                .when(realmService).createRealm(request);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () -> {
            realmController.createRealm(request);
        }, "Debe lanzar una ResponseStatusException");

        assertEquals(HttpStatus.CONFLICT, thrown.getStatusCode(), "El código de estado debe ser 409 CONFLICT");

        verify(realmService, times(1)).createRealm(request);
    }
}