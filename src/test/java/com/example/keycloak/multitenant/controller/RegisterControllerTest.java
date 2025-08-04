package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.RegisterRequest;
import com.example.keycloak.multitenant.service.KeycloakService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegisterControllerTest {

    @Mock
    private KeycloakService keycloakService;
    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private RegisterController registerController;

    private String realm;
    private String keycloakRealm;
    private Map<String, String> realmMapping;

    @BeforeEach
    void setUp() {
        realm = "plexus";
        keycloakRealm = "plexus-realm";

        realmMapping = new HashMap<>();
        realmMapping.put(realm, keycloakRealm);

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
    }

    @Test
    @DisplayName("showRegisterForm debería retornar el realm y registerRequest")
    void showRegisterForm_shouldReturnRealmInfo() {
        ResponseEntity<Map<String, Object>> responseEntity = registerController.showRegisterForm(realm);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        Map<String, Object> body = responseEntity.getBody();
        assertNotNull(body);
        assertEquals(realm, body.get("realm"));
        assertEquals(keycloakRealm, body.get("keycloakRealm"));
        assertTrue(body.get("registerRequest") instanceof RegisterRequest);
    }

    @Test
    @DisplayName("showRegisterForm debería lanzar ResponseStatusException si el realm no está mapeado")
    void showRegisterForm_shouldThrowExceptionForUnmappedRealm() {
        String unknownRealm = "unknown";
        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            registerController.showRegisterForm(unknownRealm);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Tenant " + unknownRealm + " no reconocido."));
    }

    @Test
    @DisplayName("register debería crear un usuario exitosamente")
    void register_shouldCreateUserSuccessfully() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setConfirmPassword("Password123!");

        when(keycloakService.userExistsByEmail(keycloakRealm, registerRequest.getEmail())).thenReturn(false);
        doNothing().when(keycloakService).createUser(anyString(), any(RegisterRequest.class));

        ResponseEntity<Map<String, Object>> responseEntity = registerController.register(realm, registerRequest);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.CREATED, responseEntity.getStatusCode());
        Map<String, Object> body = responseEntity.getBody();
        assertNotNull(body);
        assertEquals("User registered. Waiting for admin approval.", body.get("message"));
        assertEquals(realm, body.get("tenantId"));
        assertEquals(keycloakRealm, body.get("keycloakRealm"));

        verify(keycloakService, times(1)).userExistsByEmail(keycloakRealm, registerRequest.getEmail());
        verify(keycloakService, times(1)).createUser(keycloakRealm, registerRequest);
    }

    @Test
    @DisplayName("register debería lanzar IllegalArgumentException si las contraseñas no coinciden")
    void register_shouldThrowExceptionIfPasswordsMismatch() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setConfirmPassword("MismatchPassword!");

        verifyNoInteractions(keycloakService);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            registerController.register(realm, registerRequest);
        });

        assertEquals("Password no coinciden", exception.getMessage());
    }

    @Test
    @DisplayName("register debería lanzar IllegalArgumentException si el email ya existe")
    void register_shouldThrowExceptionIfEmailExists() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("existing@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setConfirmPassword("Password123!");

        when(keycloakService.userExistsByEmail(keycloakRealm, registerRequest.getEmail())).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            registerController.register(realm, registerRequest);
        });

        assertTrue(exception.getMessage().contains("El email 'existing@example.com' ya está registrado en Keycloak."));

        verify(keycloakService, times(1)).userExistsByEmail(keycloakRealm, registerRequest.getEmail());
        verify(keycloakService, never()).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("register debería lanzar ResponseStatusException si el realm no está mapeado")
    void register_shouldThrowExceptionForUnmappedRealm() {
        String unknownRealm = "unknown";
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("Password123!");
        registerRequest.setConfirmPassword("Password123!");

        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            registerController.register(unknownRealm, registerRequest);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Tenant " + unknownRealm + " no reconocido."));

        verifyNoInteractions(keycloakService);
    }
}
