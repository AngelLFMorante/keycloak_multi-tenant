package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.ChangePasswordRequest;
import com.example.keycloak.multitenant.model.ErrorResponse;
import com.example.keycloak.multitenant.service.ChangeOwnPasswordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para manejar la funcionalidad de cambio de contraseña del usuario.
 * <p>
 * Este controlador expone un único endpoint para que los usuarios autenticados
 * puedan cambiar su propia contraseña. La lógica de negocio se delega a
 * {@link ChangeOwnPasswordService}.
 *
 * @author Angel Fm
 * @version 1.0
 * @see ChangeOwnPasswordService
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Gestión de Password", description = "Endpoints para el cambio de password de usuario")
public class ChangePasswordController {

    private static final Logger log = LoggerFactory.getLogger(ChangePasswordController.class);

    private final ChangeOwnPasswordService changeOwnPasswordService;

    public ChangePasswordController(ChangeOwnPasswordService changeOwnPasswordService) {
        this.changeOwnPasswordService = changeOwnPasswordService;
        log.info("ChangePasswordController inicializado.");
    }

    /**
     * Endpoint para que un usuario cambie su propia contraseña.
     * <p>
     * Este método recibe el ID de usuario y la solicitud de cambio de contraseña,
     * que incluye la contraseña actual y la nueva contraseña.
     *
     * @param userId                El ID del usuario cuya contraseña se va a cambiar.
     * @param realm                 El nombre del realm (tenant) al que pertenece el usuario.
     * @param client                El ID del cliente de Keycloak.
     * @param changePasswordRequest El objeto de solicitud con las contraseñas.
     * @return {@link ResponseEntity} sin contenido si el cambio es exitoso.
     */
    @Operation(
            summary = "Cambiar contraseña de usuario",
            description = "Permite a un usuario cambiar su propia contraseña verificando la actual."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Contraseña cambiada exitosamente."),
            @ApiResponse(responseCode = "400", description = "Parámetros de entrada no válidos o campos vacíos.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Contraseña actual incorrecta.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Usuario o tenant no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{realm}/{client}/users/{userId}/change-password")
    public ResponseEntity<Void> changePassword(
            @Parameter(description = "El identificador de usuario.")
            @PathVariable String userId,
            @Parameter(description = "El identificador del realm.")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Kaycloak.")
            @PathVariable String client,
            @Parameter(description = "Objeto JSON con la password actual y la nueva.")
            @RequestBody ChangePasswordRequest changePasswordRequest) {
        log.info("Solicitud de cambio de password para el usuario '{}' en el realm '{}'.", userId, realm);

        changeOwnPasswordService.changeOwnPassword(
                realm,
                client,
                userId,
                changePasswordRequest.username(),
                changePasswordRequest.currentPassword(),
                changePasswordRequest.newPassword()
        );

        log.info("Cambio de password completado con exito para el usuario '{}'.", userId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
