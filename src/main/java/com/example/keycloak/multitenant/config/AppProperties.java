package com.example.keycloak.multitenant.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Clase que mapea las propiedades de configuración generales de la aplicación
 * desde el archivo {@code application.properties}.
 * <p>
 * Las propiedades deben tener el prefijo {@code app}.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Component
@Data
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    /**
     * La URL base del frontend o backend, utilizada para construir enlaces en correos electrónicos.
     * Por ejemplo: {@code http://localhost:8081} o {@code https://miapp.com}.
     * Esta URL debe ser accesible desde donde el usuario reciba el correo.
     */
    private String baseUrl;
}
