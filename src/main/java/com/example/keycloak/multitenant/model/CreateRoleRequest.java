package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * DTO para la solicitud de creacion de un nuevo rol en Keycloak.
 */
@Data
@Schema(description = "DTO para la creacion de un nuevo rol")
public class CreateRoleRequest {

    @NotBlank(message = "El nombre del rol no puede estar vacio")
    @Size(min = 3, max = 50, message = "EL nombre del rol debe tener entre 3 y 50 caracteres")
    @Schema(description = "Nombre del rol a crear.", example = "my_new_role")
    private String name;

    @Size(max = 255, message = "La descripcion del rol no puede exceder los 255 caracteres")
    @Schema(description = "Descripcion del rol.", example = "Rol para usuarios de prueba.")
    private String description;

}
