package com.example.keycloakdemo.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeycloakProperties {

    private String authServerUrl;
    private String singleRealmName;
    private Map<String, String> clientSecrets = new HashMap<>();

    // Nuevas propiedades para la administración de Keycloak
    private String adminRealm;
    private String adminUsername;
    private String adminPassword;
    private String adminClientId;
}
