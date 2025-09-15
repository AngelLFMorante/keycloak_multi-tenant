package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controlador web para el registro de usuarios.
 * <p>
 * Este controlador maneja los endpoints para mostrar el formulario de registro y procesar
 * la creación de nuevos usuarios a través de la interfaz web.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Controller
@RequestMapping("/{realm}")
@Tag(name = "Register Web", description = "Endpoints web para el registro de usuarios.")
public class WebRegisterController {

    private static final Logger log = LoggerFactory.getLogger(WebRegisterController.class);
    private final UserService userService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param userService Servicio que maneja la lógica de negocio para los usuarios.
     */
    public WebRegisterController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Muestra el formulario de registro para un realm y cliente específicos.
     *
     * @param realm  El nombre del realm (tenant).
     * @param client El ID del cliente de Keycloak.
     * @param model  El modelo para pasar datos a la vista.
     * @return El nombre de la vista ("register") que contiene el formulario de registro.
     */
    @Operation(
            summary = "Muestra el formulario de registro.",
            description = "Renderiza la página web con el formulario para registrar un nuevo usuario en un realm y cliente específicos."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Formulario de registro renderizado exitosamente.")
    })
    @GetMapping("/{client}/register")
    public String showRegisterForm(
            @Parameter(description = "El identificador del tenant (realm).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.", required = true)
            @PathVariable String client,
            Model model) {
        model.addAttribute("tenantId", realm);
        model.addAttribute("clientId", client);
        model.addAttribute("registerRequest", new UserRequest("", "", "", "", null));
        return "register";
    }

    /**
     * Procesa el envío del formulario de registro de un nuevo usuario.
     * <p>
     * Este método valida los datos del formulario y, si no hay errores, delega la lógica
     * de registro al servicio de usuario.
     *
     * @param realm         El nombre del realm (tenant).
     * @param client        El ID del cliente de Keycloak.
     * @param request       El objeto {@link UserRequest} que contiene los datos del usuario a registrar.
     * @param bindingResult El resultado de la validación del formulario.
     * @param model         El modelo para pasar datos a la vista.
     * @return El nombre de la vista ("register") con un mensaje de éxito o un error.
     */
    @Operation(
            summary = "Procesa el registro de un nuevo usuario.",
            description = "Recibe los datos del formulario de registro, valida la información y crea el usuario en Keycloak."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Registro exitoso. Devuelve la misma página con un mensaje de éxito."),
            @ApiResponse(responseCode = "400", description = "Error de validación o inesperado. Devuelve la misma página con un mensaje de error.")
    })
    @PostMapping("/{client}/register")
    public String processRegister(
            @Parameter(description = "El identificador del tenant (realm).", required = true)
            @PathVariable("realm") String realm,
            @Parameter(description = "El ID del cliente de Keycloak.", required = true)
            @PathVariable("client") String client,
            @Parameter(description = "Los datos del usuario para el registro.", required = true)
            @Valid @ModelAttribute("registerRequest") UserRequest request,
            BindingResult bindingResult,
            Model model) {
        model.addAttribute("tenantId", realm);
        model.addAttribute("clientId", client);

        if (bindingResult.hasErrors()) {
            return "register";
        }

        try {
            userService.registerUser(realm, request);
            model.addAttribute("message",
                    "Usuario registrado. Revisa tu email para activar la cuenta y definir contraseña.");
            return "register";
        } catch (Exception e) {
            log.error("Error en register", e);
            model.addAttribute("error", "Ocurrió un error inesperado.");
            return "register";
        }
    }
}
