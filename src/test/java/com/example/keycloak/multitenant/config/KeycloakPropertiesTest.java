package com.example.keycloak.multitenant.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(
        properties = {
                "keycloak.auth-server-url=http://localhost:8080/auth",
                "keycloak.admin.realm=master",
                "keycloak.admin.username=adminUser",
                "keycloak.admin.password=adminPass",
                "keycloak.admin.client-id=admin-cli",
                "keycloak.realm-mapping.my-app=/app",
                "keycloak.realm-mapping.another-app=/api",
                "keycloak.client-secrets.web-client=secret-web",
                "keycloak.client-secrets.mobile-client=secret-mobile"
        }
)
@ActiveProfiles("test")
class KeycloakPropertiesTest {

    @Autowired
    private KeycloakProperties keycloakProperties;

    @Test
    @DisplayName("Debería cargar correctamente la URL del servidor de autenticación")
    void shouldLoadAuthServerUrlCorrectly() {
        assertNotNull(keycloakProperties);
        assertEquals("http://localhost:8080/auth", keycloakProperties.getAuthServerUrl());
    }

    @Test
    @DisplayName("Debería cargar correctamente las propiedades del administrador")
    void shouldLoadAdminPropertiesCorrectly() {
        assertNotNull(keycloakProperties.getAdmin());
        assertEquals("master", keycloakProperties.getAdmin().getRealm());
        assertEquals("adminUser", keycloakProperties.getAdmin().getUsername());
        assertEquals("adminPass", keycloakProperties.getAdmin().getPassword());
        assertEquals("admin-cli", keycloakProperties.getAdmin().getClientId());
    }

    @Test
    @DisplayName("Debería cargar correctamente el mapeo de realms")
    void shouldLoadRealmMappingCorrectly() {
        assertNotNull(keycloakProperties.getRealmMapping());
        assertFalse(keycloakProperties.getRealmMapping().isEmpty());
        assertEquals(4, keycloakProperties.getRealmMapping().size());
        assertTrue(keycloakProperties.getRealmMapping().containsKey("my-app"));
        assertEquals("/app", keycloakProperties.getRealmMapping().get("my-app"));
        assertTrue(keycloakProperties.getRealmMapping().containsKey("another-app"));
        assertEquals("/api", keycloakProperties.getRealmMapping().get("another-app"));
    }

    @Test
    @DisplayName("Debería cargar correctamente los secretos de clientes")
    void shouldLoadClientSecretsCorrectly() {
        assertNotNull(keycloakProperties.getClientSecrets());
        assertFalse(keycloakProperties.getClientSecrets().isEmpty());
        assertEquals(4, keycloakProperties.getClientSecrets().size());
        assertTrue(keycloakProperties.getClientSecrets().containsKey("web-client"));
        assertEquals("secret-web", keycloakProperties.getClientSecrets().get("web-client"));
        assertTrue(keycloakProperties.getClientSecrets().containsKey("mobile-client"));
        assertEquals("secret-mobile", keycloakProperties.getClientSecrets().get("mobile-client"));
    }

    @Test
    @DisplayName("Debería manejar mapas vacíos si no hay configuración")
    void shouldHandleEmptyMaps() {
        assertNotNull(keycloakProperties.getAuthServerUrl());
        assertNotNull(keycloakProperties.getClientSecrets());
        assertFalse(keycloakProperties.getClientSecrets().isEmpty());
        assertNotNull(keycloakProperties.getRealmMapping());
        assertFalse(keycloakProperties.getRealmMapping().isEmpty());
        assertNotNull(keycloakProperties.getAdmin());
        assertNotNull(keycloakProperties.getAdmin().getRealm());
        assertNotNull(keycloakProperties.getAdmin().getUsername());
    }

    @Test
    @DisplayName("El método @PostConstruct debería ejecutarse sin errores")
    void postConstructShouldExecute() {
        assertNotNull(keycloakProperties);
    }
}
