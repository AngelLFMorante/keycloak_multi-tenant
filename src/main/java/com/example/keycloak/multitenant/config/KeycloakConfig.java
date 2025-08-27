package com.example.keycloak.multitenant.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuración para inicializar el cliente de administración de Keycloak (Keycloak Admin Client).
 * <p>
 * Esta configuración permite a la aplicación interactuar con la API de administración de Keycloak
 * para realizar operaciones como la creación de usuarios, la gestión de roles, clientes, etc.
 * <p>
 * Los valores de configuración para la conexión a Keycloak se obtienen de {@link KeycloakProperties}.
 * Es importante notar que el 'adminRealm' es el realm donde se autentica
 * el propio cliente de administracion, no el realm donde se gestionan los usuarios de la aplicacion.
 *
 * @author Angel Fm
 * @version 1.0
 * @see KeycloakProperties
 */
@Configuration
public class KeycloakConfig {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfig.class);

    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para inyección de dependencias de las propiedades de Keycloak.
     *
     * @param keycloakProperties Las propiedades de configuración de Keycloak, cargadas desde {@code application.yml} o {@code application.properties}.
     */
    public KeycloakConfig(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Define y configura un bean de {@link Keycloak}.
     * <p>
     * Este bean proporciona una instancia del cliente de administración de Keycloak,
     * autenticado con las credenciales del administrador proporcionadas.
     *
     * @return Una instancia configurada y autenticada de {@link Keycloak} admin client.
     */
    @Bean
    public Keycloak keycloak() {
        log.info("Configurando el cliente de administracion de Keycloack...");
        log.debug("Server URL: {}", keycloakProperties.getAuthServerUrl());
        log.debug("Admin Realm: {}", keycloakProperties.getAdmin().getRealm());
        log.debug("Admin Username: {}", keycloakProperties.getAdmin().getUsername());
        log.debug("Admin Client ID: {}", keycloakProperties.getAdmin().getClientId());

        // Construye una instancia de Keycloak Admin Client utilizando KeycloakBuilder.
        Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getAuthServerUrl())
                .realm(keycloakProperties.getAdmin().getRealm())
                .username(keycloakProperties.getAdmin().getUsername())
                .password(keycloakProperties.getAdmin().getPassword())
                .clientId(keycloakProperties.getAdmin().getClientId())
                .build();

        log.info("Cliente de administracion de Keycloak configurado exitosamente");
        return keycloakAdminClient;
    }
}
