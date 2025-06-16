package com.example.keycloakdemo.controller;

import java.security.Principal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.stream.Collectors;

@Controller
public class HomeController {

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


    @GetMapping("/{tenant}/login")
    public String redirectToTenantLogin(@PathVariable String tenant) {
        return "redirect:/oauth2/authorization/" + tenant;
    }

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
            model.addAttribute("accessToken", oidcUser.getIdToken().getTokenValue()); // Note: This is ID Token, not Access Token itself. For Access Token, you might need to save it from the userRequest.
            return "home"; // Renders src/main/resources/templates/tenant-home.html
        }
        return "redirect:/"; // Redirect to public index if not authenticated
    }
}