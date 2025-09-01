package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import java.util.Map;

/**
 * @param userWithRoles
 * @param attributes
 * @author Angel Fm
 * @version 1.1
 */
@Schema(description = "Representación de un usuario con sus roles y atributos personalizados.")
public record UserWithRolesAndAttributes(
        @Schema(description = "Información básica del usuario con sus roles.")
        UserWithRoles userWithRoles,
        @Schema(description = "Atributos personalizados del usuario.", example = "{\"organization\": [\"Plexus\"], \"department\": [\"IT\"]}")
        Map<String, List<String>> attributes
) {
}
