package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.service.PasswordFlowService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controlador web para gestionar el flujo de restablecimiento de contraseña y la activación de usuarios
 * a través de un enlace de verificación por correo electrónico.
 * <p>
 * Este controlador maneja las vistas y lógica de la parte web para verificar tokens y
 * permitir a los usuarios establecer una nueva contraseña.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Controller
@RequestMapping("/{realm}/password")
@Tag(name = "Password Flow", description = "Operaciones del flujo de contraseña y activación de usuarios.")
public class PasswordWebController {

    private static final Logger log = LoggerFactory.getLogger(PasswordWebController.class);

    private final PasswordFlowService flow;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param flow Servicio que maneja la lógica de negocio para el flujo de contraseñas.
     */
    public PasswordWebController(PasswordFlowService flow) {
        this.flow = flow;
    }

    /**
     * Verifica el token de correo electrónico proporcionado para el flujo de restablecimiento de contraseña
     * y muestra la página para establecer la nueva contraseña.
     *
     * @param realm El nombre del realm (tenant).
     * @param token El token de verificación enviado por correo electrónico.
     * @param model El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista (página web) a renderizar.
     */
    @Operation(
            summary = "Verifica un token de correo electrónico para el flujo de contraseña.",
            description = "Valida el token y, si es válido, dirige al usuario a la página para establecer la contraseña."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token válido. Redirecciona a la página para establecer la contraseña."),
            @ApiResponse(responseCode = "400", description = "Token inválido o expirado.")
    })
    @GetMapping("/verify")
    public String verify(
            @Parameter(description = "El nombre del realm (tenant).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El token de verificación enviado por correo electrónico.", required = true)
            @RequestParam String token,
            Model model) {
        try {
            log.info("Verificando token para el realm '{}'", realm);
            flow.verifyEmail(realm, token);
            model.addAttribute("realm", realm);
            model.addAttribute("token", token);
            return "set-password";
        } catch (Exception e) {
            log.error("Error al verificar token: {}", e.getMessage());
            model.addAttribute("error", "El enlace no es válido o ha expirado");
            return "verify-error";
        }
    }

    /**
     * Procesa la solicitud para establecer la nueva contraseña de un usuario.
     *
     * @param realm    El nombre del realm (tenant).
     * @param token    El token de verificación de correo.
     * @param password La nueva contraseña a establecer.
     * @param model    El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista (página web) a renderizar.
     */
    @Operation(
            summary = "Establece una nueva contraseña para el usuario.",
            description = "Recibe el token y la nueva contraseña para actualizar las credenciales del usuario en Keycloak."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Contraseña establecida con éxito."),
            @ApiResponse(responseCode = "400", description = "No fue posible establecer la contraseña.")
    })
    @PostMapping("/set")
    public String setPassword(
            @Parameter(description = "El nombre del realm (tenant).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El token de verificación.", required = true)
            @RequestParam String token,
            @Parameter(description = "La nueva contraseña.", required = true)
            @RequestParam String password,
            Model model) {
        try {
            log.info("Intentando establecer contraseña para el realm '{}'", realm);
            flow.setPassword(realm, token, password);
            model.addAttribute("message", "¡Contraseña definida! Espera activación del admin.");
            return "set-password-success";
        } catch (Exception e) {
            log.error("Error al establecer la contraseña: {}", e.getMessage());
            model.addAttribute("error", "No fue posible establecer la contraseña");
            model.addAttribute("token", token);
            return "set-password";
        }
    }
}
