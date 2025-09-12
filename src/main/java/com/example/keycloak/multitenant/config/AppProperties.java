package com.example.keycloak.multitenant.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Data
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    /**
     * URL base del frontend/back donde vive el endpoint set-password.
     * Ej: https://miapp.com
     */
    private String baseUrl;
}
