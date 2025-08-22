package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakUtilsServiceTest {

    @Mock
    private Keycloak keycloak;

    @Mock
    private RealmResource realmResource;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private KeycloakUtilsService keycloakUtilsService;

    private String realmName = "tenant1";
    private String mappedRealm = "internal-realm";

    @Test
    @DisplayName("Debería retornar RealmResource cuando el realm existe")
    void getRealmResource_Success() {
        when(keycloak.realm(anyString())).thenReturn(realmResource);
        RealmResource result = keycloakUtilsService.getRealmResource("testRealm");

        assertNotNull(result);
        verify(keycloak, times(1)).realm("testRealm");
    }

    @Test
    @DisplayName("Debería resolver correctamente el realm mapeado")
    void resolveRealm_Success() {
        Map<String, String> mapping = new HashMap<>();
        mapping.put(realmName, mappedRealm);

        when(keycloakProperties.getRealmMapping()).thenReturn(mapping);

        String result = keycloakUtilsService.resolveRealm(realmName);

        assertEquals(mappedRealm, result);
        verify(keycloakProperties, times(1)).getRealmMapping();
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si no existe mapeo para el realm")
    void resolveRealm_NotFound() {
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                keycloakUtilsService.resolveRealm(realmName)
        );

        assertTrue(exception.getReason().contains("Realm " + realmName + " no reconocido"));
        assertEquals(404, exception.getStatusCode().value());
        verify(keycloakProperties, times(1)).getRealmMapping();
    }
}
