package com.example.keycloakdemo.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuración para inicializar el cliente de administración de Keycloak (Keycloak Admin Client).
 * Esta configuración permite a la aplicación interactuar con la API de administración de Keycloak
 * para realizar operaciones como la creación de usuarios, la gestión de roles, clientes, etc.
 *
 * Los valores de configuración para la conexión a Keycloak se inyectan desde
 * los archivos de propiedades.
 * Es importante notar que el 'adminRealm' es master el realm donde se autentica
 * el propio cliente de administracion, no el realm donde se gestionan los usuarios de la aplicacion.
 */
@Configuration
public class KeycloakConfig {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfig.class);

    /**
     * URL base del servidor de autenticación de Keycloak.
     * Ejemplo: http://localhost:8080
     */
    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    /**
     * Nombre del realm de Keycloak que se utilizará para la autenticación del usuario administrador
     * del cliente de administración. Generalmente es "master".
     */
    @Value("${keycloak.admin.realm}")
    private String adminRealm;

    /**
     * Nombre de usuario del administrador de Keycloak.
     * Este usuario debe tener los privilegios adecuados en el 'adminRealm'
     * para realizar las operaciones deseadas a través del cliente de administración.
     */
    @Value("${keycloak.admin.username}")
    private String adminUsername;

    /**
     * Contraseña del usuario administrador de Keycloak.
     * Esta contraseña se utiliza para autenticar el cliente de administración.
     */
    @Value("${keycloak.admin.password}")
    private String adminPassword;

    /**
     * ID del cliente de Keycloak que se utiliza para la autenticación del administrador.
     * Por defecto, para el CLI de administración, suele ser "admin-cli".
     */
    @Value("${keycloak.admin.client-id}")
    private String adminClientId;

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
        log.debug("Server URL: {}", serverUrl);
        log.debug("Admin Realm: {}", adminRealm);
        log.debug("Admin Username: {}", adminUsername);
        log.debug("Admin Client ID: {}", adminClientId);

        // Construye una instancia de Keycloak Admin Client utilizando KeycloakBuilder.
         Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl) // Establece la URL del servidor de Keycloak.
                .realm(adminRealm)    // Establece el realm para la autenticación del administrador.
                .username(adminUsername) // Establece el nombre de usuario del administrador.
                .password(adminPassword) // Establece la contraseña del administrador.
                .clientId(adminClientId) // Establece el ID del cliente para la autenticación del administrador.
                .build(); // Construye la instancia del cliente Keycloak.

        log.info("Cliente de administracion de Keycloak configurado exitosamente");
        return keycloakAdminClient;
    }
}
