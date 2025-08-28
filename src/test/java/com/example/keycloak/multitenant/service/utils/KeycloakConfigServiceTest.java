package com.example.keycloak.multitenant.service.utils;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakConfigServiceTest {

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private KeycloakConfigService keycloakConfigService;

    @Test
    @DisplayName("Debería resolver el nombre del realm correctamente si el mapeo existe")
    void resolveRealm_shouldReturnKeycloakRealm_whenMappingExists() {
        String publicRealm = "tenant1";
        String keycloakRealm = "tenant1-realm";
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(publicRealm, keycloakRealm);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);

        String result = keycloakConfigService.resolveRealm(publicRealm);

        assertEquals(keycloakRealm, result);
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el mapeo del realm no existe")
    void resolveRealm_shouldThrowException_whenMappingDoesNotExist() {
        String publicRealm = "non-existent-tenant";
        Map<String, String> realmMapping = new HashMap<>();
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            keycloakConfigService.resolveRealm(publicRealm);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertEquals("Realm " + publicRealm + " no reconocido", exception.getReason());
    }
}
