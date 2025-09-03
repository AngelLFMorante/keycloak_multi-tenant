package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Un record para la solicitud de creación de un nuevo realm.
 *
 * <p>Representa la estructura de datos esperada en el cuerpo de una solicitud HTTP
 * para crear un nuevo realm en Keycloak.</p>
 *
 * @param realmName El nombre del realm a crear. No puede ser nulo o vacío.
 */
@Schema(
        description = "Un objeto de solicitud para crear un nuevo realm en Keycloak."
)
public record RealmCreationRequest(
        @NotEmpty
        @JsonProperty("realm")
        @Schema(
                description = "El nombre del nuevo realm a crear. Debe ser único.",
                example = "nuevo-realm"
        )
        String realmName
) {
}
