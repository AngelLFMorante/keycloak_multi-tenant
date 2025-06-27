package com.example.keycloakdemo.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * Controlador para manejar las rutas públicas de la aplicación y las páginas
 * de inicio protegidas por tenant, mostrando información del usuario autenticado.
 */
@Controller
public class HomeController {

    /**
     * Maneja la solicitud GET para la página de inicio pública ("/").
     * Determina si el usuario está autenticado y añade un mensaje al modelo
     * basado en el estado de autenticación.
     *
     * @param model          El objeto {@link Model} para pasar datos a la vista.
     * @param authentication El objeto {@link Authentication} que representa
     * al usuario actualmente autenticado (puede ser null si no hay usuario).
     * @return El nombre de la vista ("index") a renderizar.
     */
    @GetMapping("/")
    public String index(Model model, Authentication authentication) {
        // Verifica si el objeto Authentication no es nulo y si el usuario está autenticado.
        boolean isLoggedIn = authentication != null && authentication.isAuthenticated();
        model.addAttribute("isLoggedIn", isLoggedIn); // Añade el estado de login al modelo.

        if (isLoggedIn) {
            // Si el usuario está logueado, añade un mensaje personalizado con su nombre.
            model.addAttribute("message", "You are logged in as " + authentication.getName());
        } else {
            // Si el usuario no está logueado, añade un mensaje por defecto.
            model.addAttribute("message", "You are not logged in.");
        }

        return "index"; // Retorna el nombre de la vista "index.html".
    }

    /**
     * Maneja la solicitud GET para la página de login específica de un tenant.
     * Añade el ID del tenant al modelo y redirige a la vista de login.
     *
     * @param tenant El nombre del tenant extraído de la URL (ej., "plexus", "inditex").
     * @param model  El objeto {@link Model} para pasar datos a la vista.
     * @return El nombre de la vista ("login") a renderizar.
     */
    @GetMapping("/{tenant}/login")
    public String redirectToTenantLogin(@PathVariable String tenant, Model model) {
        model.addAttribute("tenantId", tenant); // Añade el ID del tenant al modelo.
        return "login"; // Retorna el nombre de la vista "login.html".
    }

    /**
     * Página de inicio protegida por tenant. Solo accesible por usuarios autenticados.
     * Recupera la información del usuario de la sesión HTTP (donde el LoginController la guarda)
     * y la expone al modelo para ser mostrada en la vista.
     *
     * @param realmName Nombre del realm (tenant) extraído de la URL.
     * @param model     El objeto {@link Model} para pasar datos a la vista.
     * @param session   La sesión HTTP actual, utilizada para recuperar los atributos del usuario.
     * @return El nombre de la vista ("home") si el usuario está autenticado y los datos están en sesión,
     * o una redirección a la página de login del tenant si no se encuentran los datos.
     */
    @GetMapping("/{realmName}/home")
    public String tenantHome(@PathVariable String realmName, Model model, HttpSession session) {
        // Intenta recuperar el nombre de usuario de la sesión HTTP.
        // El LoginController es responsable de guardar esta información en la sesión.
        Object username = session.getAttribute("username");

        // Verifica si el nombre de usuario está presente en la sesión.
        // Si username es null, significa que el usuario no está autenticado o la sesión expiró/se perdió.
        if (username != null) {
            // Si el usuario está autenticado, añade sus detalles al modelo desde la sesión.
            model.addAttribute("realmName", realmName); // Nombre del realm (tenant).
            model.addAttribute("username", username); // Nombre de usuario.
            model.addAttribute("email", session.getAttribute("email")); // Email del usuario.
            model.addAttribute("fullName", session.getAttribute("fullName")); // Nombre completo del usuario.
            model.addAttribute("roles", session.getAttribute("roles")); // Lista de roles del usuario.
            model.addAttribute("accessToken", session.getAttribute("accessToken")); // Access Token de Keycloak.

            return "home"; // Retorna el nombre de la vista "home.html".
        }

        // Si el usuario no está autenticado o la información no está en la sesión,
        // redirige a la página de login específica del tenant para que se autentique.
        return "redirect:/" + realmName + "/login";
    }
}
