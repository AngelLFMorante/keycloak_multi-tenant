package com.example.keycloakdemo.model;

import lombok.Data; // Importa la anotación @Data de Lombok.

/**
 * Clase que representa el objeto de solicitud para el registro de un nuevo usuario.
 * Utiliza la anotación {@link lombok.Data} de Lombok para generar automáticamente
 * los getters, setters, toString(), equals() y hashCode().
 */
@Data
public class RegisterRequest {
    /**
     * El nombre de usuario deseado para el nuevo registro.
     */
    private String username;

    /**
     * La contraseña para el nuevo usuario.
     */
    private String password;

    /**
     * Campo para confirmar la contraseña, asegurando que el usuario la ha introducido correctamente.
     * Es utilizado para validación en el lado de la aplicación antes de enviar a Keycloak.
     */
    private String confirmPassword;

    /**
     * La dirección de correo electrónico del usuario.
     */
    private String email;

    /**
     * El primer nombre del usuario.
     */
    private String firstName;

    /**
     * El apellido del usuario.
     */
    private String lastName;
}