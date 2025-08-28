package com.example.keycloak.multitenant.service.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakAdminServiceTest {

    @Mock
    private Keycloak keycloak;

    @Mock
    private RealmResource realmResource;

    @InjectMocks
    private KeycloakAdminService keycloakAdminService;

    @Test
    @DisplayName("Debería obtener un RealmResource para el realm especificado")
    void getRealmResource_shouldReturnRealmResource_whenRealmIsValid() {
        String realm = "test-realm";
        when(keycloak.realm(realm)).thenReturn(realmResource);

        RealmResource result = keycloakAdminService.getRealmResource(realm);

        assertNotNull(result);
        assertSame(realmResource, result);
    }
}
