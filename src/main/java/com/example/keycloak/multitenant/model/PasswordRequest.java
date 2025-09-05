package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Representa el DTO (Data Transfer Object) para una solicitud de cambio de contraseña.
 * Este record inmutable encapsula la nueva contraseña proporcionada por el usuario.
 * <p>
 * Se utiliza en las peticiones API para garantizar que la contraseña se pase de forma
 * segura y estructurada, facilitando la validación y el procesamiento del dato.
 * </p>
 *
 * @param newPassword La nueva contraseña que se desea establecer.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "DTO para solicitar un cambio de contraseña.")
public record PasswordRequest(
        @Schema(description = "La nueva contraseña para el usuario.", example = "NewPassword123!")
        String newPassword) {
}