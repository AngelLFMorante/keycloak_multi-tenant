package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * @param id
 * @param username
 * @param email
 * @param firstName
 * @param lastName
 * @param enabled
 * @param emailVerified
 * @param roles
 * @author Angel Fm
 * @version 1.1
 */
@Schema(description = "Representación de un usuario junto con sus roles y estado de cuenta.")
public record UserWithRoles(
        @Schema(description = "ID único del usuario en Keycloak.", example = "1234-5678-90")
        String id,
        @Schema(description = "Nombre de usuario.", example = "john.doe")
        String username,
        @Schema(description = "Correo electrónico del usuario.", example = "john.doe@example.com")
        String email,
        @Schema(description = "Nombre.", example = "John")
        String firstName,
        @Schema(description = "Apellido.", example = "Doe")
        String lastName,
        @Schema(description = "Estado de habilitación de la cuenta.", example = "true")
        boolean enabled,
        @Schema(description = "Estado de verificación del correo electrónico.", example = "true")
        boolean emailVerified,
        @Schema(description = "Lista de roles asociados al usuario.", example = "[\"admin\", \"user\"]")
        List<String> roles
) {
}