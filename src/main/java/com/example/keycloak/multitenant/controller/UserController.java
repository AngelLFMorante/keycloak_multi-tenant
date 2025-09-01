package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.model.UserSearchCriteria;
import com.example.keycloak.multitenant.model.UserWithRoles;
import com.example.keycloak.multitenant.model.UserWithRolesAndAttributes;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para gestionar el ciclo de vida de los usuarios en Keycloak.
 * <p>
 * Proporciona endpoints para registrar, obtener, actualizar y eliminar usuarios
 * en un entorno multi-tenant. Las operaciones se delegan a {@link UserService}.
 *
 * @author Angel Fm
 * @version 1.0
 * @see UserService
 */
@RestController
@RequestMapping("/api/v1/{realm}/users")
@Tag(name = "User Management", description = "Operaciones para la gestion de usuarios en Keycloak.")
public class UserController {

    private static Logger log = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param userService El servicio de usuarios que maneja la lógica de negocio.
     */
    public UserController(UserService userService) {
        this.userService = userService;
        log.info("UserController inicializado.");
    }

    /**
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * <p>
     * Recibe los datos de registro como JSON en el cuerpo de la solicitud, realiza la validación
     * y delega la creación del usuario a {@link UserService}.
     *
     * @param realm   El nombre del tenant (realm) para el que se registra el usuario.
     * @param request El objeto {@link UserRequest} que contiene los datos del usuario.
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
     * @return Una {@link ResponseEntity} que contiene una lista de {@link UserWithRoles}.
     */
    @Operation(
            summary = "Obtiene todos los usuarios",
            description = "Recupera una lista de todos los usuarios en un realm de Keycloak con sus roles."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping
    public ResponseEntity<List<UserWithRoles>> getAllUsers(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm) {
        log.info("Solicitud para obtener todos los usuarios del tenant: {}", realm);
        List<UserWithRoles> users = userService.getAllUsers(realm);
        log.info("Lista de {} usuarios obtenida con éxito.", users.size());
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para actualizar un usuario por su ID.
     *
     * @param realm       El nombre del realm (tenant).
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos del usuario actualizados.
     * @return Una {@link ResponseEntity} vacía con estado OK.
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
     * @return Una {@link ResponseEntity} vacía con estado NO_CONTENT.
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

    /**
     * Endpoint para obtener un usuario por ID junto con sus roles.
     * <p>
     * Este método gestiona la solicitud GET para recuperar la información completa
     * de un usuario, incluyendo sus atributos y roles, a partir de su ID.
     *
     * @param realm  El nombre del realm (tenant).
     * @param userId El ID del usuario en formato UUID.
     * @return Una {@link ResponseEntity} con el objeto {@link UserWithRoles}
     * si el usuario es encontrado, o una respuesta de error 404 si no lo es.
     */
    @Operation(
            summary = "Obtiene un usuario por su ID",
            description = "Recupera la información del usuario y sus roles en una sola respuesta."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario recuperado con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/{userId}")
    public ResponseEntity<UserWithRoles> getUserById(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a obtener.")
            @PathVariable UUID userId) {
        log.info("Iniciando solicitud para obtener el usuario con ID '{}' del tenant: {}", userId, realm);
        UserWithRoles userDetails = userService.getUserById(realm, userId.toString());
        log.info("Usuario con ID '{}' recuperado exitosamente del tenant '{}'", userId, realm);
        return ResponseEntity.ok(userDetails);
    }

    /**
     * Endpoint para obtener un usuario por su email.
     *
     * @param realm El nombre del realm (tenant).
     * @param email El correo electrónico del usuario a buscar.
     * @return Una {@link ResponseEntity} con el objeto {@link UserWithRoles}
     * si el usuario es encontrado, o una respuesta de error 404 si no lo es.
     */
    @Operation(
            summary = "Obtiene un usuario por su email",
            description = "REcupera la información del usaurio y sus roles en una sola respuesta."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario recuperado con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles.class))),
            @ApiResponse(responseCode = "404", description = "Realm o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/email/{email}")
    public ResponseEntity<UserWithRoles> getUserByEmail(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "El email del usuario a obtener.")
            @PathVariable String email
    ) {
        log.info("Iniciando solicitud para obtener el usuario con el email '{}' del realm '{}'", email, realm);
        UserWithRoles userDetails = userService.getUserByEmail(realm, email);
        log.info("Usuario con email '{}' recuperado exitosamente del realm '{}'", email, realm);
        return ResponseEntity.ok(userDetails);
    }

    /**
     * Endpoint para obtener una lista de usuarios por atributos personalizados.
     * <p>
     * Este método delega la búsqueda a la capa de servicio. Los parámetros de
     * búsqueda se pasan como query parameters, lo cual es una buena práctica para GET.
     *
     * @param realm        El nombre del realm (tenant).
     * @param organization Atributo de la organización para filtrar.
     * @param subsidiary   Atributo de la filial para filtrar.
     * @param department   Atributo del departamento para filtrar.
     * @return Una {@link ResponseEntity} que contiene una lista de {@link UserWithRolesAndAttributes}.
     */
    @Operation(
            summary = "Obtiene usuarios por atributos personalizados",
            description = "Busca y filtra una lista de usuarios en un realm por sus atributos personalizados (organizacion, filial, departamento)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con exito.",
                    content = @Content(schema = @Schema(implementation = UserWithRolesAndAttributes[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/attributes")
    public ResponseEntity<List<UserWithRolesAndAttributes>> getUsersByAttributes(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "Filtra por la organización.")
            @RequestParam(required = false) String organization,
            @Parameter(description = "Filtra por la filial.")
            @RequestParam(required = false) String subsidiary,
            @Parameter(description = "Filtra por el departamento.")
            @RequestParam(required = false) String department) {
        log.info("Solicitud de busqueda por atributos para el realm '{}'", realm);
        log.debug("Criterios de búsqueda recibidos: organizacion='{}', filial='{}', departamento='{}'.", organization, subsidiary, department);
        UserSearchCriteria criteria = new UserSearchCriteria(organization, subsidiary, department);
        List<UserWithRolesAndAttributes> users = userService.getUsersByAttributes(realm, criteria);
        log.info("Busqueda completada. {} usuarios encontrados.", users.size());
        return ResponseEntity.ok(users);
    }
}
