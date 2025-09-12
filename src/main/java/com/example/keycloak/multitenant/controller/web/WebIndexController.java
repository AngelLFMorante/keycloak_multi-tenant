package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.LoginResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebIndexController {

    @GetMapping("/")
    public String index(HttpSession session, Model model) {
        // Comprobar login
        LoginResponse loginResponse = (LoginResponse) session.getAttribute("loginResponse");
        boolean isLoggedIn = loginResponse != null;
        model.addAttribute("isLoggedIn", isLoggedIn);

        // Prellenar campos de realm/client
        if (loginResponse != null) {
            model.addAttribute("tenantId", loginResponse.getRealm());
            model.addAttribute("clientId", loginResponse.getClient());
        } else {
            // Valores por defecto
            model.addAttribute("tenantId", "realm");
            model.addAttribute("clientId", "my-client");
        }

        return "index";
    }
}
