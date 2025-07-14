package com.example.keycloakdemo.config;

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
    private String singleRealmName;
    private Map<String, String> clientSecrets = new HashMap<>();

    private Admin admin = new Admin(); // ¡Importante inicializarla!

    @Data // Anotación de Lombok para la clase anidada
    public static class Admin { // Debe ser 'public static' para que Spring pueda instanciarla
        private String realm;
        private String username;
        private String password;
        private String clientId; // Mapea a keycloak.admin.client-id
    }
    // <-- FIN de la clase anidada -->

    @PostConstruct
    public void init() {
        log.info("--- Propiedades Keycloak cargadas (dentro de @PostConstruct) ---");
        log.info("  authServerUrl: {}", authServerUrl);
        log.info("  singleRealmName: {}", singleRealmName);
        log.info("  clientSecrets: {}", clientSecrets);

        // Accede a las propiedades admin a través del objeto 'admin'
        if (admin != null) {
            log.info("  adminRealm: {}", admin.getRealm());
            log.info("  adminUsername: {}", admin.getUsername());
            log.info("  adminPassword: {}", admin.getPassword() != null && !admin.getPassword().isEmpty() ? "******" : "null/empty");
            log.info("  adminClientId: {}", admin.getClientId());
        } else {
            log.info("  Objeto 'admin' es null. Las propiedades de admin no se están enlazando.");
        }
        log.info("---------------------------------------------------------------");
    }
}