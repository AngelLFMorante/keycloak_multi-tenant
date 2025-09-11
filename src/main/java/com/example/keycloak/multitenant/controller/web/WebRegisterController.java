package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Controller
@RequestMapping("/{realm}")
public class WebRegisterController {

    private static final Logger log = LoggerFactory.getLogger(WebRegisterController.class);

    private final KeycloakUserService userService;

    public WebRegisterController(KeycloakUserService userService) {
        this.userService = userService;
    }

    @GetMapping("/register")
    public String showRegisterForm(@PathVariable String realm, Model model) {
        model.addAttribute("realm", realm);
        model.addAttribute("registerRequest", new UserRequest("", "", "", "", null));
        return "register";
    }

    @PostMapping("/register")
    public String processRegister(@PathVariable String realm,
                                  @Valid @ModelAttribute("registerRequest") UserRequest registerRequest,
                                  BindingResult bindingResult,
                                  Model model) {

        model.addAttribute("realm", realm);

        if (bindingResult.hasErrors()) {
            log.warn("Errores en formulario de registro: {}", bindingResult.getAllErrors());
            return "register";
        }

        try {
            // Validar si el email ya existe
            if (userService.userExistsByEmail(realm, registerRequest.email())) {
                model.addAttribute("error", "El email ya está registrado");
                return "register";
            }

            // Generar contraseña temporal aleatoria
            String tempPassword = UUID.randomUUID().toString();

            // Crear usuario en Keycloak con contraseña temporal
            userService.createUserWithRole(realm, registerRequest, tempPassword);

            model.addAttribute("message", "Registro completado correctamente. Se ha generado una contraseña temporal.");
            return "register";

        } catch (Exception e) {
            log.error("Error inesperado durante el registro", e);
            model.addAttribute("error", "Ocurrió un error inesperado. Intente nuevamente más tarde.");
            return "register";
        }
    }
}
