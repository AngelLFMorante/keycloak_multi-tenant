package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;

/**
 * Un record para la solicitud de creación de un nuevo cliente.
 *
 * <p>Representa la estructura de datos esperada en el cuerpo de una solicitud HTTP
 * para crear un nuevo cliente en un realm de Keycloak.</p>
 *
 * @param realmName  El nombre del realm donde se creará el cliente.
 * @param clientName El ID del nuevo cliente.
 */
@Schema(
        description = "Un objeto de solicitud para crear un nuevo cliente en un realm específico."
)
public record ClientCreationRequest(
        @NotEmpty
        @JsonProperty("realm")
        @Schema(
                description = "El nombre del realm donde se creará el cliente.",
                example = "demo-realm"
        )
        String realmName,

        @NotEmpty
        @JsonProperty("client")
        @Schema(
                description = "El ID del nuevo cliente a crear.",
                example = "demo-client"
        )
        String clientName
) {
}