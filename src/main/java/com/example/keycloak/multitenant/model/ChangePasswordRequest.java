package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Record para representar la solicitud de cambio de contraseña.
 * Contiene los datos necesarios para que un usuario cambie su propia contraseña.
 * <p>
 * Un record en Java es una clase inmutable y transparente, ideal para
 * ser usada como un DTO (Data Transfer Object).
 *
 * @param username        El nombre de usuario del cliente que realiza la solicitud.
 * @param currentPassword La contraseña actual del usuario, para su validación.
 * @param newPassword     La nueva contraseña que se desea establecer.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "Solicitud para el cambio de contraseña de un usuario.")
public record ChangePasswordRequest(

        @Schema(description = "Nombre de usuario del cliente.", example = "johndoe")
        @NotBlank(message = "El nombre de usuario no puede estar en blanco.")
        String username,

        @Schema(description = "Contraseña actual del usuario para su validación.", example = "password123")
        @NotBlank(message = "La contraseña actual no puede estar en blanco.")
        String currentPassword,

        @Schema(description = "Nueva contraseña del usuario.", example = "newStrongPassword!1")
        @NotBlank(message = "La nueva contraseña no puede estar en blanco.")
        String newPassword
) {
}