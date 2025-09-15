package com.example.keycloak.multitenant.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Clase que mapea las propiedades de configuración de JWT (JSON Web Token)
 * desde el archivo {@code application.properties}.
 * <p>
 * Las propiedades deben tener el prefijo {@code app.jwt}.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Component
@Data
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    /**
     * La clave secreta utilizada para firmar el JWT.
     * Esta clave debe ser lo suficientemente larga y segura para evitar
     * que los tokens sean manipulados.
     */
    private String secret;

    /**
     * El tiempo de expiración del token en horas.
     * El valor por defecto es de 12 horas si no se especifica.
     */
    private long expirationHours = 12;

}
