package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Clase que representa el objeto de solicitud para el registro de un nuevo usuario modelo Keycloak register.
 */
@Data
@Schema(description = "DTO para la solicitud de registro o actualizacion de un usuario.")
public class UserRequest {
    /**
     * El nombre de usuario deseado para el nuevo registro.
     */
    @NotBlank(message = "El nombre de usuario no puede estar vacio")
    @Schema(description = "Nombre de usuario unico para el nuevo usuario.", example = "john.doe")
    private String username;

    /**
     * La dirección de correo electrónico del usuario.
     */
    @NotBlank(message = "El email no puede estar vacio")
    @Email(message = "El email debe tener un formato valido")
    @Schema(description = "Direccion de correo electronico del usuario.", example = "john.doe@example.com")
    private String email;

    /**
     * El primer nombre del usuario.
     */
    @NotBlank(message = "El nombre no puede estar vacio")
    @Schema(description = "Primer nombre del usuario.", example = "John")
    private String firstName;

    /**
     * El apellido del usuario.
     */
    @NotBlank(message = "El apellido no puede estar vacio")
    @Schema(description = "Apellido del usuario.", example = "Doe")
    private String lastName;

    /**
     * Rol que se le asignará en Keycloak.
     */
    @Schema(description = "El rol de Keycloak que se asignara al usuario. Opcional.", example = "user")
    private String role;
}