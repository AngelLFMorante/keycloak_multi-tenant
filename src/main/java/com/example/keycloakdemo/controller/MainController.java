package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.services.KeycloakAdminService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
class MainController {

    @Autowired
    private KeycloakAdminService keycloakAdminService;

    @GetMapping("/")
    public String index() {
        return "redirect:/login"; // Asegúrate de usar una barra inicial para rutas absolutas
    }

    // --- AÑADE ESTE MÉTODO ---
    @GetMapping("/login")
    public String login(Model model) {
        // Puedes pasar un tenantId por defecto o manejarlo dinámicamente si tienes múltiples logins.
        // Por ahora, usamos "plexus" como ejemplo, ya que tu formulario de login usa th:text="|Login - ${tenantId.toUpperCase()}|"
        model.addAttribute("tenantId", "plexus");
        return "login"; // Asume que tienes un archivo login.html en src/main/resources/templates
    }
    // -------------------------

    @GetMapping("/home")
    public String home(Model model, Authentication authentication) {
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        model.addAttribute("username", user.getAttribute("preferred_username"));
        model.addAttribute("email", user.getAttribute("email"));
        model.addAttribute("tenantId", "plexus");
        return "home";
    }

    @GetMapping("/pending")
    public String pendingApproval(Model model, Authentication authentication) {
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        model.addAttribute("username", user.getAttribute("preferred_username"));
        model.addAttribute("tenantId", "plexus");
        return "pending-approval";
    }

    // Tu @PostMapping para el login personalizado de Keycloak
    // Considera si este POST debe ser a "/login" o a "/plexus/login"
    // Si tu formulario apunta a "/login" en el action, debería ser @PostMapping("/login")
    // Si tienes un formulario por cada tenant, entonces el actual está bien, pero tu <form th:action="@{/login}" method="post">
    // en login.html apunta a "/login", no a "/plexus/login". Esto es una inconsistencia.
    @PostMapping("/login") // CAMBIO AQUÍ: para que coincida con el action de tu formulario de login
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          Model model,
                          HttpSession session) {
        try {
            String realm = "plexus"; // O un parámetro si manejas múltiples realms
            String clientId = "mi-spring-app-plexus";
            String clientSecret = "0Fqax8FO1Pkjdd6RQFoJ8m0dYLCXu1zl";

            String token = keycloakAdminService.obtainToken(realm, clientId, clientSecret, username, password);

            boolean approved = keycloakAdminService.isUserVerified("plexus", username);
            if (!approved) {
                return "redirect:/pending";
            }
            session.setAttribute("token", token);
            session.setAttribute("username", username);
            return "redirect:/home";
        } catch (Exception e) {
            model.addAttribute("error", "Credenciales inválidas");
            model.addAttribute("tenantId", "plexus"); // Asegúrate de pasar el tenantId de nuevo
            return "login";
        }
    }
}