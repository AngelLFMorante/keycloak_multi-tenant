package com.example.keycloak.multitenant.model.user;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * @param organization Atributo de organización del usuario.
 * @param subsidiary   Atributo de filial del usuario.
 * @param department   Atributo de departamento del usuario.
 * @author Angel Fm
 * @version 1.1
 */
@Schema(description = "Criterios para buscar usuarios por atributos personalizados.")
public record UserSearchCriteria(
        @Schema(description = "Filtra por la organizacion del usuario.", example = "Plexus")
        String organization,
        @Schema(description = "Filtra por la filial del usuario.", example = "ES")
        String subsidiary,
        @Schema(description = "Filtra por el departamento del usuario.", example = "IT")
        String department
) {
}