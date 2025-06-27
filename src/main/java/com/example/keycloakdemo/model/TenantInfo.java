package com.example.keycloakdemo.model;

/**
 * <p>
 * Clase de tipo "record" que representa la información específica de un tenant (inquilino)
 * en el contexto de una aplicación multi-tenant integrada con Keycloak.
 * </p>
 * <p>
 * Un record es una característica de Java que proporciona una forma concisa de declarar
 * clases que son principalmente portadoras de datos. Los componentes del record
 * automáticamente se convierten en campos finales, se generan métodos `equals()`,
 * `hashCode()`, `toString()`, y métodos de acceso (getters).
 * </p>
 *
 * @param realm        Nombre del realm en Keycloak asociado a este tenant. Este es el espacio
 * lógico en Keycloak donde se gestionan los usuarios y la configuración
 * de seguridad para este inquilino.
 * @param clientId     Identificador único del cliente (aplicación) configurado en Keycloak
 * para este tenant. Es usado para identificar la aplicación cliente
 * durante los flujos de autenticación OAuth2/OIDC.
 * @param clientSecret Secreto del cliente. Es una credencial confidencial usada por el cliente
 * para autenticarse con Keycloak, especialmente en flujos como
 * el "Authorization Code Flow" con PKCE o "Client Credentials Flow".
 * Debe mantenerse seguro y nunca exponerse en el lado del cliente (frontend).
 */
public record TenantInfo(String realm, String clientId, String clientSecret) {}
