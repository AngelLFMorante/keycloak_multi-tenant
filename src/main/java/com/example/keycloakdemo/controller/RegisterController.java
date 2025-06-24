package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.model.RegisterRequest;
import com.example.keycloakdemo.service.KeycloakService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class RegisterController {

    private final KeycloakService keycloakService;

    public RegisterController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    @GetMapping("/{realm}/register")
    public String showRegisterForm(@PathVariable String realm, Model model) {
        model.addAttribute("realm", realm);
        model.addAttribute("registerRequest", new RegisterRequest());
        return "register";
    }


    @PostMapping("/{realm}/register")
    public String register(@PathVariable String realm, @ModelAttribute RegisterRequest request, Model model) {
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            model.addAttribute("error", "Passwords do not match");
            return "register"; // misma vista que tú ya usas
        }

        try {
            realm = realm.concat("-realm");
            keycloakService.createUser(realm, request);
            model.addAttribute("message", "User registered. Waiting for admin approval.");
            model.addAttribute("tenantId", realm);
            return "login"; // tu vista de login
        } catch (Exception e) {
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
        }
    }
}
