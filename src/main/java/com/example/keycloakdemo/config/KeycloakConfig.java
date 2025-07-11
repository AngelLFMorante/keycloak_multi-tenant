package com.example.keycloakdemo.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// import org.springframework.beans.factory.annotation.Value; // <--- Ya no es necesario
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuración para inicializar el cliente de administración de Keycloak (Keycloak Admin Client).
 * Esta configuración permite a la aplicación interactuar con la API de administración de Keycloak
 * para realizar operaciones como la creación de usuarios, la gestión de roles, clientes, etc.
 *
 * Los valores de configuración para la conexión a Keycloak se obtienen de {@link KeycloakProperties}.
 * Es importante notar que el 'adminRealm' es master el realm donde se autentica
 * el propio cliente de administracion, no el realm donde se gestionan los usuarios de la aplicacion.
 */
@Configuration
public class KeycloakConfig {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfig.class);

    // Inyectamos KeycloakProperties directamente
    private final KeycloakProperties keycloakProperties;

    // Constructor para inyectar KeycloakProperties
    public KeycloakConfig(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Define y configura un bean de {@link Keycloak}.
     * Este bean proporciona una instancia del cliente de administración de Keycloak,
     * autenticado con las credenciales del administrador proporcionadas.
     *
     * @return Una instancia configurada y autenticada de {@link Keycloak} admin client.
     */
    @Bean
    public Keycloak keycloak() {
        log.info("Configurando el cliente de administracion de Keycloack...");
        log.debug("Server URL: {}", keycloakProperties.getAuthServerUrl()); // Usar de KeycloakProperties
        log.debug("Admin Realm: {}", keycloakProperties.getAdminRealm());      // Usar de KeycloakProperties
        log.debug("Admin Username: {}", keycloakProperties.getAdminUsername()); // Usar de KeycloakProperties
        log.debug("Admin Client ID: {}", keycloakProperties.getAdminClientId()); // Usar de KeycloakProperties

        // Construye una instancia de Keycloak Admin Client utilizando KeycloakBuilder.
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getAuthServerUrl()) // Obtener de KeycloakProperties
                .realm(keycloakProperties.getAdminRealm())        // Obtener de KeycloakProperties
                .username(keycloakProperties.getAdminUsername())  // Obtener de KeycloakProperties
                .password(keycloakProperties.getAdminPassword())  // Obtener de KeycloakProperties
                .clientId(keycloakProperties.getAdminClientId())  // Obtener de KeycloakProperties
                .build(); // Construye la instancia del cliente Keycloak.

        log.info("Cliente de administracion de Keycloak configurado exitosamente");
        return keycloakAdminClient;
    }
}
