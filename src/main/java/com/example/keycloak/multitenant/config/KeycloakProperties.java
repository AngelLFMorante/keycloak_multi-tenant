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
 * Clase de configuración que carga las propiedades de Keycloak.
 * <p>
 * Se enlaza a las propiedades definidas en el archivo de configuración de la aplicación
 * (ej. {@code application.yml}) bajo el prefijo {@code keycloak}. Esta clase
 * centraliza toda la configuración necesaria para conectar y operar con Keycloak.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Configuration
@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeycloakProperties {

    private static final Logger log = LoggerFactory.getLogger(KeycloakProperties.class);

    /**
     * URL del servidor de autenticación de Keycloak.
     * <p>
     * Ejemplo en YAML: {@code keycloak.auth-server-url: http://localhost:8080/auth}
     */
    private String authServerUrl;

    /**
     * Mapa que contiene los secretos de los clientes de Keycloak.
     * <p>
     * La clave es el ID del cliente y el valor es su secreto. Permite la configuración
     * de múltiples clientes de forma centralizada.
     * <p>
     * Ejemplo en YAML:
     * <pre>{@code
     * keycloak:
     * client-secrets:
     * client1: secret123
     * client2: secret456
     * }</pre>
     */
    private Map<String, String> clientSecrets = new HashMap<>();

    /**
     * Mapa que define el mapeo de identificadores de tenant a nombres de realms de Keycloak.
     * <p>
     * Esto es útil en una configuración multi-tenant, donde un nombre de tenant en la URL
     * de la API se traduce a un nombre de realm real en Keycloak.
     * <p>
     * Ejemplo en YAML:
     * <pre>{@code
     * keycloak:
     * realm-mapping:
     * tenant-a: a-realm
     * tenant-b: b-realm
     * }</pre>
     */
    private Map<String, String> realmMapping = new HashMap<>();

    /**
     * Objeto anidado que contiene las propiedades de configuración para el cliente
     * administrador de Keycloak.
     */
    private Admin admin = new Admin();

    /**
     * Clase estática anidada que representa las propiedades del cliente de administración.
     * <p>
     * Estas credenciales se utilizan para que la aplicación se autentique en el realm
     * de administración (generalmente el 'master' realm) y pueda realizar operaciones
     * administrativas a través de la API de Keycloak.
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
     * Método de inicialización que se ejecuta después de que las propiedades han sido inyectadas.
     * <p>
     * Este método registra la configuración cargada, lo cual es de gran utilidad para
     * la depuración y para verificar que las propiedades se han enlazado correctamente.
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