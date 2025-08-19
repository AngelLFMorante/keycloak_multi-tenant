package com.example.keycloak.multitenant.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Clase que representa el objeto de solicitud para el registro de un nuevo usuario modelo Keycloak register.
 */
@Data
public class UserRequest {
    /**
     * El nombre de usuario deseado para el nuevo registro.
     */
    @NotBlank(message = "El nombre de usuario no puede estar vacio")
    private String username;

    /**
     * La dirección de correo electrónico del usuario.
     */
    @NotBlank(message = "El email no puede estar vacio")
    @Email(message = "El email debe tener un formato valido")
    private String email;

    /**
     * El primer nombre del usuario.
     */
    @NotBlank(message = "El nombre no puede estar vacio")
    private String firstName;

    /**
     * El apellido del usuario.
     */
    @NotBlank(message = "El apellido no puede estar vacio")
    private String lastName;

    /**
     * Rol que se le asignará en Keycloak.
     */
    @NotBlank(message = "El rol no puede estar vacío")
    private String role;
}