package com.example.keycloakdemo.model;

/**
 * Representa la información específica de un tenant (inquilino),
 * incluyendo el nombre del realm, el clientId y el clientSecret.
 *
 * @param realm        Nombre del realm en Keycloak.
 * @param clientId     Identificador del cliente configurado en Keycloak.
 * @param clientSecret Secreto del cliente, necesario si el cliente es confidencial.
 */
public record TenantInfo(String realm, String clientId, String clientSecret) {}
