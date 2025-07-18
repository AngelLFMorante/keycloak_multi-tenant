package com.example.keycloak.multitenant.config;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuración para las propiedades de Keycloak.
 * Esta clase se encarga de cargar las propiedades relacionadas con Keycloak desde el archivo
 * de configuración de la aplicación (por ejemplo, `application.properties` o `application.yml`)
 * utilizando el prefijo "keycloak".
 */
@Configuration
@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeycloakProperties {

    private static final Logger log = LoggerFactory.getLogger(KeycloakProperties.class);

    /**
     * URL del servidor de autenticación de Keycloak.
     */
    private String authServerUrl;

    /**
     * Mapa que contiene los secretos de los clientes de Keycloak, donde la clave es el ID del cliente
     * y el valor es el secreto del cliente.
     * Esto permite configurar múltiples secretos de cliente para diferentes clientes.
     */
    private Map<String, String> clientSecrets = new HashMap<>();

    /**
     * Mapa que define el mapeo de rutas o identificadores a realms de Keycloak.
     * La clave podría ser una ruta URL o un identificador lógico, y el valor el nombre del realm.
     * Esto es útil en configuraciones multi-tenant donde diferentes rutas acceden a diferentes realms.
     */
    private Map<String, String> realmMapping = new HashMap<>();

    /**
     * Objeto anidado que contiene las propiedades de configuración para el usuario administrador de Keycloak.
     */
    private Admin admin = new Admin();

    /**
     * Clase estática anidada que representa las propiedades de configuración para el usuario administrador de Keycloak.
     */
    @Data
    public static class Admin {
        /**
         * Nombre del realm de administración.
         */
        private String realm;
        /**
         * Nombre de usuario del administrador.
         */
        private String username;
        /**
         * Contraseña del administrador.
         */
        private String password;
        /**
         * ID del cliente asociado al administrador.
         */
        private String clientId;
    }

    /**
     * Metodo de inicialización que se ejecuta después de que todas las propiedades han sido inyectadas.
     * Registra información sobre las propiedades de Keycloak cargadas, incluyendo la URL del servidor,
     * los detalles del administrador, los mapeos de realms y los IDs de los clientes con secretos configurados.
     * Se utiliza para depuración y para verificar que las propiedades se han enlazado correctamente.
     */
    @PostConstruct
    public void init() {
        log.info("--- Propiedades Keycloak cargadas (dentro de @PostConstruct) ---");
        log.info("  authServerUrl: {}", authServerUrl);

        if (admin != null) {
            log.info("  Admin Realm: {}", admin.getRealm());
            log.info("  Admin Username: {}", admin.getUsername());
            log.info("  Admin Client ID: {}", admin.getClientId());
            log.info("  Admin Password: {}", admin.getPassword() != null && !admin.getPassword().isEmpty() ? "******" : "[No Configurada]");
        } else {
            log.warn("  Objeto 'admin' es nulo. Las propiedades de admin no se están enlazando.");
        }

        if (realmMapping != null && !realmMapping.isEmpty()) {
            log.info("  Mapeo de Realms configurado:");
            realmMapping.forEach((path, realm) -> log.info("    - Path '{}' -> Realm '{}'", path, realm));
        } else {
            log.warn("  No se encontraron mapeos de realms configurados.");
        }

        if (clientSecrets != null && !clientSecrets.isEmpty()) {
            log.info("  Secretos de Clientes configurados (solo IDs):");
            clientSecrets.keySet().forEach(clientId -> log.info("    - Client ID: {}", clientId));
        } else {
            log.warn("  No se encontraron secretos de clientes configurados.");
        }
        log.info("---------------------------------------------------------------");
    }
}