package com.example.keycloak.multitenant.config;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeycloakProperties {

    private static final Logger log = LoggerFactory.getLogger(KeycloakProperties.class);

    private String authServerUrl;
    private Map<String, String> clientSecrets = new HashMap<>();
    private Map<String, String> realmMapping = new HashMap<>();

    private Admin admin = new Admin();

    @Data
    public static class Admin {
        private String realm;
        private String username;
        private String password;
        private String clientId;
    }

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