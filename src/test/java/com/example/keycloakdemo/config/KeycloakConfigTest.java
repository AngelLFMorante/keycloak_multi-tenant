package com.example.keycloakdemo.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Clase de test unitario para {@link KeycloakConfig}.
 * Verifica que el bean {@link Keycloak} (cliente de administración de Keycloak)
 * se crea y configura correctamente con las propiedades inyectadas.
 */
class KeycloakConfigTest {

    private KeycloakConfig keycloakConfig;

    private String adminRealm = "master";
    private String adminUsername = "testadmin";
    private String adminPassword = "testpassword";
    private String adminClientId = "test-admin-cli";

    @BeforeEach
    void setUp() {
        keycloakConfig = new KeycloakConfig();
        // Inyectar manualmente los valores de las propiedades @Value en el objeto de configuración
        // Propiedades de prueba para simular los valores @Value
        String serverUrl = "http://mock-keycloak:8080";
        ReflectionTestUtils.setField(keycloakConfig, "serverUrl", serverUrl);
        ReflectionTestUtils.setField(keycloakConfig, "adminRealm", adminRealm);
        ReflectionTestUtils.setField(keycloakConfig, "adminUsername", adminUsername);
        ReflectionTestUtils.setField(keycloakConfig, "adminPassword", adminPassword);
        ReflectionTestUtils.setField(keycloakConfig, "adminClientId", adminClientId);
    }

    @Test
    @DisplayName("Debería crear una instancia de Keycloak Admin Client")
    void keycloak_BeanCreation() {
        Keycloak keycloakAdminClient = keycloakConfig.keycloak();

        assertNotNull(keycloakAdminClient, "El cliente de administración de Keycloak no debería ser nulo");
        // No hay una forma directa de verificar las propiedades internas de KeycloakBuilder
        // a través de la instancia de Keycloak devuelta, ya que es un objeto construido.
        // Sin embargo, la ausencia de excepciones y la no nulidad indican que la construcción fue exitosa.
        // Para una verificación más profunda de la configuración, se requeriría inspección de objetos internos
        // o tests de integración.
    }
}
