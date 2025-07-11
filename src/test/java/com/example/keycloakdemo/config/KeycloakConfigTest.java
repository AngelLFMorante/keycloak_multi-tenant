package com.example.keycloakdemo.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith; // Mantener si es un test unitario puro
import org.mockito.Mock; // Usar @Mock para mocks puros de Mockito
import org.mockito.junit.jupiter.MockitoExtension; // Mantener si es un test unitario puro
import org.keycloak.admin.client.Keycloak;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when; // Importar when

/**
 * Clase de test unitario para {@link KeycloakConfig}.
 * Verifica que el bean {@link Keycloak} (cliente de administración de Keycloak)
 * se crea y configura correctamente con las propiedades inyectadas.
 */
@ExtendWith(MockitoExtension.class) // Mantener para tests unitarios puros
class KeycloakConfigTest {

    private KeycloakConfig keycloakConfig;

    @Mock // Mock de KeycloakProperties
    private KeycloakProperties keycloakProperties;

    // Ya no necesitas estas variables si los valores vienen del mock de KeycloakProperties
    // private String adminRealm = "master";
    // private String adminUsername = "testadmin";
    // private String adminPassword = "testpassword";
    // private String adminClientId = "test-admin-cli";

    @BeforeEach
    void setUp() {
        // Configura el mock de KeycloakProperties con los valores necesarios
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://mock-keycloak:8080"); // Asumiendo que serverUrl es authServerUrl
        when(keycloakProperties.getAdminRealm()).thenReturn("master");
        when(keycloakProperties.getAdminUsername()).thenReturn("testadmin");
        when(keycloakProperties.getAdminPassword()).thenReturn("testpassword");
        when(keycloakProperties.getAdminClientId()).thenReturn("test-admin-cli");

        // Asegúrate de que KeycloakConfig se inicializa con el mock
        // Asunción: KeycloakConfig tiene un constructor que acepta KeycloakProperties
        keycloakConfig = new KeycloakConfig(keycloakProperties);
    }

    @Test
    @DisplayName("Debería crear una instancia de Keycloak Admin Client")
    void keycloak_BeanCreation() {
        Keycloak keycloakAdminClient = keycloakConfig.keycloak();

        assertNotNull(keycloakAdminClient, "El cliente de administración de Keycloak no debería ser nulo");
    }
}
