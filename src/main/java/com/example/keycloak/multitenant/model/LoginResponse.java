package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import lombok.Data;

/**
 * DTO (Data Transfer Object) que encapsula la respuesta de autenticacion o
 * renovacion de token del servidor de Keycloak.
 * <p>
 * Contiene los tokens JWT, asi como informacion relevante del usuario y los
 * roles extraidos del token de acceso.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Data
@Schema(description = "Respuesta de autenticacion o renovacion de token que contiene los tokens y la informacion del usuario.")
public class LoginResponse {

    /**
     * El token de acceso JWT (JSON Web Token).
     * <p>
     * Se utiliza para acceder a los recursos protegidos de la aplicacion.
     */
    @Schema(description = "El token de acceso JWT.", example = "eyJ...")
    private String accessToken;

    /**
     * El token de identidad JWT.
     * <p>
     * Contiene informacion sobre la identidad del usuario autenticado.
     */
    @Schema(description = "El token de identidad JWT.", example = "eyJ...")
    private String idToken;

    /**
     * El token de renovacion.
     * <p>
     * Se utiliza para obtener un nuevo token de acceso una vez que el actual ha expirado.
     */
    @Schema(description = "El token de renovacion para obtener un nuevo token de acceso.", example = "eyJ...")
    private String refreshToken;

    /**
     * Tiempo de vida del token de acceso en segundos.
     */
    @Schema(description = "Tiempo de vida del access token en segundos.", example = "300")
    private long expiresIn;

    /**
     * Tiempo de vida del token de renovacion en segundos.
     */
    @Schema(description = "Tiempo de vida del refresh token en segundos.", example = "1800")
    private long refreshExpiresIn;

    /**
     * El nombre de usuario.
     */
    @Schema(description = "El nombre de usuario.", example = "user.test")
    private String username;

    /**
     * La direccion de correo electronico del usuario.
     */
    @Schema(description = "La direccion de correo electronico del usuario.", example = "user@test.com")
    private String email;

    /**
     * El nombre completo del usuario.
     */
    @Schema(description = "El nombre completo del usuario.", example = "Test User")
    private String fullName;

    /**
     * Una lista de los roles asignados al usuario.
     */
    @Schema(description = "Una lista de los roles asignados al usuario.", example = "['ROLE_USER', 'ROLE_ADMIN']")
    private List<String> roles;

    /**
     * El identificador del tenant (realm) al que pertenece el usuario.
     */
    @Schema(description = "El identificador del tenant (realm).", example = "tenant1")
    private String realm;

    /**
     * El ID del cliente de Keycloak.
     */
    @Schema(description = "El ID del cliente de Keycloak.", example = "mi-app-plexus")
    private String client;

    /**
     * El nombre de usuario preferido, extraido del token JWT.
     */
    @Schema(description = "El nombre de usuario preferido extraido del token JWT.", example = "user.test")
    private String preferredUsername;

    /**
     * Constructor para la respuesta de autenticacion completa.
     * <p>
     * Incluye todos los tokens, asi como la informacion detallada del usuario
     * y los roles.
     */
    public LoginResponse(String accessToken, String idToken, String refreshToken, long expiresIn, long refreshExpiresIn,
                         String username, String email, String fullName, List<String> roles, String realm, String client, String preferredUsername) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.username = username;
        this.email = email;
        this.fullName = fullName;
        this.roles = roles;
        this.realm = realm;
        this.client = client;
        this.preferredUsername = preferredUsername;
    }

    /**
     * Constructor para la respuesta de renovacion de token.
     * <p>
     * Se utiliza cuando solo se necesitan los nuevos tokens, sin necesidad
     * de la informacion detallada del usuario.
     */
    public LoginResponse(String accessToken, String idToken, String refreshToken, long expiresIn, long refreshExpiresIn,
                         String realm, String client) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.realm = realm;
        this.client = client;
    }
}