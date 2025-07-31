package com.example.keycloak.multitenant.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * DTO para la solicitud de creacion de un nuevo rol en Keycloak.
 */
@Data
public class CreateRoleRequest {

    @NotBlank(message = "El nombre del rol no puede estar vacio")
    @Size(min = 3, max = 50, message = "EL nombre del rol debe tener entre 3 y 50 caracteres")
    private String name;

    @Size(max = 255, message = "La descripcion del rol no puede exceder los 255 caracteres")
    private String description;

}
