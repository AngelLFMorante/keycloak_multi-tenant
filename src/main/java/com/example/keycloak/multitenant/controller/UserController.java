package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para gestionar el proceso de registro de nuevos usuarios en Keycloak.
 * Maneja la visualización del formulario de registro y el procesamiento de la solicitud de registro.
 * La creación de usuarios en Keycloak se delega a {@link UserService}.
 */
@RestController
@RequestMapping("/api/v1/{realm}/users")
@Tag(name = "User Management", description = "Operaciones para la gestion de usuarios en Keycloak.")
public class UserController {

    private static Logger log = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    /**
     * Constructor para la inyección de dependencias.
     **/
    public UserController(UserService userService) {
        this.userService = userService;
        log.info("UserController inicializado.");
    }

    /**
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * Recibe los datos de registro como JSON en el cuerpo de la solicitud.
     * Realiza una validación básica de contraseñas y luego delega la creación del usuario
     * a {@link UserService}. Devuelve JSON con el estado de la operación.
     *
     * @param realm   El nombre del tenant extraído de la URL. Este `realm`
     *                se usará para cualquier lógica específica del cliente si fuera necesario,
     *                pero el registro de usuario se hace en el `singleKeycloakRealm` principal.
     * @param request El objeto {@link UserRequest} que contiene los datos del formulario de registro,
     *                recibido del cuerpo de la solicitud JSON.
     * @return Un {@link ResponseEntity} con el estado de éxito o error del registro.
     */
    @Operation(
            summary = "Registra un nuevo usuario",
            description = "Crea un nuevo usuario en Keycloak con una contrasena temporal y lo deshabilita hasta la aprobacion del administrador."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "400", description = "Datos de registro invalidos.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Valid @RequestBody UserRequest request) {
        log.info("Intento de registro de usuario para el tenant: {}", realm);
        Map<String, Object> response = userService.registerUser(realm, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint para obtener la lista de todos los usuarios en un realm.
     *
     * @param realm El nombre del realm (tenant).
     * @return Una lista de {@link UserRepresentation} con los usuarios.
     */
    @Operation(
            summary = "Obtiene todos los usuarios",
            description = "Recupera una lista de todos los usuarios en un realm de Keycloak."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con exito.",
                    content = @Content(schema = @Schema(implementation = UserRepresentation[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping
    public ResponseEntity<List<UserRepresentation>> getAllUsers(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm) {
        log.info("Solicitud para obtener todos los usuarios del tenant: {}", realm);
        List<UserRepresentation> users = userService.getAllUsers(realm);
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para actualizar un usuario por su ID.
     *
     * @param realm       El nombre del realm (tenant).
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos del usuario actualizados.
     * @return Una respuesta vacía con estado OK.
     */
    @Operation(
            summary = "Actualiza un usuario",
            description = "Actualiza la informacion de un usuario existente por su ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario actualizado con exito."),
            @ApiResponse(responseCode = "404", description = "Tenant o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PutMapping("/{userId}")
    public ResponseEntity<Void> updateUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a actualizar.")
            @PathVariable UUID userId,
            @RequestBody UserRequest updatedUser) {
        log.info("Solicitud para actualizar el usuario con ID '{}' del tenant: {}", userId, realm);
        userService.updateUser(realm, userId.toString(), updatedUser);
        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint para eliminar un usuario por su ID.
     *
     * @param realm  El nombre del realm (tenant).
     * @param userId El ID del usuario a eliminar.
     * @return Una respuesta vacía con estado NO_CONTENT.
     */
    @Operation(
            summary = "Elimina un usuario",
            description = "Elimina un usuario de un realm por su ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Usuario eliminado con exito."),
            @ApiResponse(responseCode = "404", description = "Tenant o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a eliminar.")
            @PathVariable UUID userId) {
        log.info("Solicitud para eliminar el usuario con ID '{}' del tenant: {}", userId, realm);
        userService.deleteUser(realm, userId.toString());
        return ResponseEntity.noContent().build();
    }
}
