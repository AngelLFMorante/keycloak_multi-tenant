package com.example.keycloakdemo.controller;

import java.security.Principal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.stream.Collectors;

/**
 * Controlador para manejar rutas públicas y protegidas por tenant.
 */
@Controller
public class HomeController {

    /**
     * Página de inicio pública. Si el usuario está autenticado, se muestra su información.
     *
     * @param model     Modelo de vista.
     * @param principal Información del usuario autenticado (si existe).
     * @return Vista index.
     */
    @GetMapping("/")
    public String index(Model model, Principal principal) {
        if (principal != null) {
            model.addAttribute("message", "Logged in as: " + principal.getName());
            model.addAttribute("isLoggedIn", true);
        } else {
            model.addAttribute("message", "You are not logged in.");
            model.addAttribute("isLoggedIn", false);
        }
        return "index";
    }

    /**
     * Redirige al flujo de login del tenant correspondiente.
     *
     * @param tenant Nombre del tenant desde la URL.
     * @return Redirección al endpoint de autorización OAuth2 para ese tenant.
     */
    @GetMapping("/{tenant}/login")
    public String redirectToTenantLogin(@PathVariable String tenant) {
        return "redirect:/oauth2/authorization/" + tenant;
    }

    /**
     * Página de inicio protegida por tenant, disponible después del login.
     *
     * @param realmName     Nombre del realm extraído de la URL.
     * @param model         Modelo de vista.
     * @param authentication Objeto de autenticación que contiene información del usuario.
     * @return Vista de usuario autenticado o redirección al inicio si no autenticado.
     */
    @GetMapping("/{realmName}/home")
    public String tenantHome(@PathVariable String realmName, Model model, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            model.addAttribute("realmName", realmName);
            model.addAttribute("username", oidcUser.getPreferredUsername());
            model.addAttribute("email", oidcUser.getEmail());
            model.addAttribute("fullName", oidcUser.getFullName());
            model.addAttribute("roles", authentication.getAuthorities().stream()
                    .map(a -> a.getAuthority())
                    .collect(Collectors.joining(", ")));
            model.addAttribute("accessToken", oidcUser.getIdToken().getTokenValue());
            return "home";
        }
        return "redirect:/";
    }
}
