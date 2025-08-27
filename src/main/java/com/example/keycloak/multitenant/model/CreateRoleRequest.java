package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Record DTO para la solicitud de creacion de un nuevo rol en Keycloak.
 * <p>
 * Este objeto encapsula los datos necesarios para crear un rol, incluyendo
 * el nombre y una descripcion opcional. Las validaciones de Jakarta Bean
 * Validation se aplican para asegurar la integridad de los datos de entrada.
 *
 * @param name        El nombre unico del rol. Es un campo obligatorio y tiene
 *                    restricciones de tamano.
 * @param description Una descripcion opcional para el rol.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "DTO para la creacion de un nuevo rol")
public record CreateRoleRequest(
        @NotBlank(message = "El nombre del rol no puede estar vacio")
        @Size(min = 3, max = 50, message = "EL nombre del rol debe tener entre 3 y 50 caracteres")
        @Schema(description = "Nombre del rol a crear.", example = "my_new_role")
        String name,

        @Size(max = 255, message = "La descripcion del rol no puede exceder los 255 caracteres")
        @Schema(description = "Descripcion del rol.", example = "Rol para usuarios de prueba.")
        String description
) {
}