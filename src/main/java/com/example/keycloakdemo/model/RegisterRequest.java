package com.example.keycloakdemo.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Clase que representa el objeto de solicitud para el registro de un nuevo usuario modelo Keycloak register.
 */
@Data
public class RegisterRequest {
    /**
     * El nombre de usuario deseado para el nuevo registro.
     */
    @NotBlank(message = "El nombre de usuario no puede estar vacio")
    private String username;

    /**
     * La contraseña para el nuevo usuario.
     */
    @NotBlank(message = "La contraseña no puede estar vacia")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    /**
     * Campo para confirmar la contraseña, asegurando que el usuario la ha introducido correctamente.
     * Es utilizado para validación en el lado de la aplicación antes de enviar a Keycloak.
     */
    @NotBlank(message = "La confirmacion de contraseña no puede estar vacio")
    private String confirmPassword;

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
}