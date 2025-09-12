package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.service.PasswordFlowService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/{realm}")
public class PasswordWebController {

    private final PasswordFlowService flow;

    public PasswordWebController(PasswordFlowService flow) {
        this.flow = flow;
    }

    @GetMapping("/verify")
    public String verify(@PathVariable String realm, @RequestParam String token, Model model) {
        try {
            flow.verifyEmail(realm, token);
            model.addAttribute("realm", realm);
            model.addAttribute("token", token);
            return "set-password";
        } catch (Exception e) {
            model.addAttribute("error", "El enlace no es válido o ha expirado");
            return "verify-error";
        }
    }

    @PostMapping("/set-password")
    public String setPassword(@PathVariable String realm,
                              @RequestParam String token,
                              @RequestParam String password,
                              Model model) {
        try {
            flow.setPassword(realm, token, password);
            model.addAttribute("message", "¡Contraseña definida! Espera activación del admin.");
            return "set-password-success";
        } catch (Exception e) {
            model.addAttribute("error", "No fue posible establecer la contraseña");
            model.addAttribute("token", token);
            return "set-password";
        }
    }
}

