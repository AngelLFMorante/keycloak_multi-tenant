package com.example.keycloak.multitenant.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Data
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    /**
     * Clave secreta usada para firmar el JWT.
     */
    private String secret;

    /**
     * Horas de expiración del token.
     */
    private long expirationHours = 12;

}
