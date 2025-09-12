package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.service.UserService;
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

@Controller
@RequestMapping("/{realm}")
public class WebRegisterController {

    private static final Logger log = LoggerFactory.getLogger(WebRegisterController.class);
    private final UserService userService;

    public WebRegisterController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{client}/register")
    public String showRegisterForm(@PathVariable String realm,
                                   @PathVariable String client,
                                   Model model) {
        model.addAttribute("tenantId", realm);
        model.addAttribute("clientId", client);
        model.addAttribute("registerRequest", new UserRequest("", "", "", "", null));
        return "registro";
    }

    @PostMapping("/{client}/register")
    public String processRegister(@PathVariable String realm,
                                  @PathVariable String client,
                                  @Valid @ModelAttribute("registerRequest") UserRequest request,
                                  BindingResult bindingResult,
                                  Model model) {
        model.addAttribute("tenantId", realm);
        model.addAttribute("clientId", client);

        if (bindingResult.hasErrors()) return "registro";

        try {
            userService.registerUser(realm, request);
            model.addAttribute("message",
                    "Usuario registrado. Revisa tu email para activar la cuenta y definir contraseña.");
            return "registro";
        } catch (Exception e) {
            log.error("Error en registro", e);
            model.addAttribute("error", "Ocurrió un error inesperado.");
            return "registro";
        }
    }
}

