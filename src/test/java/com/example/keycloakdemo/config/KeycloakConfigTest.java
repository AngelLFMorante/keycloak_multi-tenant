package com.example.keycloakdemo.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.keycloak.admin.client.Keycloak;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link KeycloakConfig}.
 * Verifica que el bean {@link Keycloak} (cliente de administración de Keycloak)
 * se crea y configura correctamente con las propiedades inyectadas.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakConfigTest {

    private KeycloakConfig keycloakConfig;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private KeycloakProperties.Admin keycloakAdminProperties;

    @BeforeEach
    void setUp() {
        when(keycloakProperties.getAdmin()).thenReturn(keycloakAdminProperties);
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://mock-keycloak:8080");
        when(keycloakAdminProperties.getRealm()).thenReturn("master");
        when(keycloakAdminProperties.getUsername()).thenReturn("testadmin");
        when(keycloakAdminProperties.getPassword()).thenReturn("testpassword");
        when(keycloakAdminProperties.getClientId()).thenReturn("test-admin-cli");

        keycloakConfig = new KeycloakConfig(keycloakProperties);
    }

    @Test
    @DisplayName("Debería crear una instancia de Keycloak Admin Client")
    void keycloak_BeanCreation() {
        Keycloak keycloakAdminClient = keycloakConfig.keycloak();

        assertNotNull(keycloakAdminClient, "El cliente de administración de Keycloak no debería ser nulo");
    }
}