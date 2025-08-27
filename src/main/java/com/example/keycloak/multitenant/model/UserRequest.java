package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Record DTO (Data Transfer Object) para la solicitud de registro o actualizacion de un usuario.
 * <p>
 * Este objeto encapsula los datos necesarios para crear o modificar un usuario
 * en Keycloak. Las validaciones de Jakarta Bean Validation se aplican para
 * asegurar la integridad de los datos de entrada.
 *
 * @param username  El nombre de usuario unico. Es un campo obligatorio.
 * @param email     La direccion de correo electronico del usuario. Es un campo
 *                  obligatorio y debe tener un formato de email valido.
 * @param firstName El primer nombre del usuario. Es un campo obligatorio.
 * @param lastName  El apellido del usuario. Es un campo obligatorio.
 * @param role      El rol de Keycloak que se asignara al usuario. Este campo es
 *                  opcional y puede ser nulo si no se desea asignar un rol por defecto.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "DTO para la solicitud de registro o actualizacion de un usuario.")
public record UserRequest(
        @NotBlank(message = "El nombre de usuario no puede estar vacio")
        @Schema(description = "Nombre de usuario unico para el nuevo usuario.", example = "john.doe")
        String username,

        @NotBlank(message = "El email no puede estar vacio")
        @Email(message = "El email debe tener un formato valido")
        @Schema(description = "Direccion de correo electronico del usuario.", example = "john.doe@example.com")
        String email,

        @NotBlank(message = "El nombre no puede estar vacio")
        @Schema(description = "Primer nombre del usuario.", example = "John")
        String firstName,

        @NotBlank(message = "El apellido no puede estar vacio")
        @Schema(description = "Apellido del usuario.", example = "Doe")
        String lastName,

        @Schema(description = "El rol de Keycloak que se asignara al usuario. Opcional.", example = "user")
        String role
) {
}