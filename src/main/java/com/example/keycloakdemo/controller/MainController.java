package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.services.KeycloakAdminService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User; // Mantén si usas oauth2Login en algún otro lugar
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
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login(Model model, @RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "logout", required = false) String logout) {
        model.addAttribute("tenantId", "plexus");
        if (error != null) {
            // Usa un mensaje más genérico si la lógica de error no es granular en el controller
            model.addAttribute("error", "Usuario o contraseña incorrectos.");
        }
        if (logout != null) {
            model.addAttribute("logout", "Has cerrado sesión correctamente.");
        }
        return "login";
    }

    @GetMapping("/home")
    public String home(Model model, Authentication authentication) {
        if (authentication != null) {
            model.addAttribute("username", authentication.getName()); // Obtiene el nombre del principal autenticado
            // Si necesitas otros atributos (como email), asegúrate de que estén disponibles
            // en tu objeto Authentication (ej. si usas un UserDetails personalizado o OAuth2User)
            // Para el caso de UsernamePasswordAuthenticationToken, solo getName() es directamente accesible.
            // Si quieres email, podrías tener que obtenerlo de Keycloak y guardarlo en la sesión o un objeto UserDetails personalizado.
        }
        model.addAttribute("tenantId", "plexus");
        return "home";
    }

    @GetMapping("/pending")
    public String pendingApproval(Model model, Authentication authentication) {
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
        }
        model.addAttribute("tenantId", "plexus");
        return "pending-approval";
    }

    // *** CAMBIO AQUÍ: La ruta del POST ahora debe ser '/do_login' ***
    @PostMapping("/do_login") // <--- ¡NUEVA RUTA!
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpSession session) {
        try {
            //Hay que cambiar estas variables para hacerlas globales
            String realm = "plexus-realm";
            String clientId = "mi-spring-app-plexus";
            String clientSecret = "APE7Jo7L22EY8yTKh50v6B82nQ8l3f24";

            // Autenticación con Keycloak
            String token = keycloakAdminService.obtainToken(realm, clientId, clientSecret, username, password);

            // Verificación de aprobación
            boolean approved = keycloakAdminService.isUserVerified("plexus", username);
            if (!approved) {
                return "redirect:/pending";
            }

            // Si todo es exitoso, establece la autenticación en Spring Security
            // No necesitas pasar el token y username a la sesión para que Spring Security funcione,
            // pero pueden ser útiles si tu aplicación los usa más tarde.
            session.setAttribute("token", token);
            session.setAttribute("username", username);

            // Creamos un UsernamePasswordAuthenticationToken. Como ya obtuvimos el token de Keycloak,
            // las credenciales (password) ya no son necesarias aquí, por eso null.
            // Las authorities (roles/permisos) se pueden añadir aquí si las obtienes de Keycloak.
            // Por simplicidad, lo dejamos null.
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Redirige al home
            return "redirect:/home";

        } catch (Exception e) {
            System.err.println("Error de login: " + e.getMessage());
            // Redirige al login con el parámetro 'error'
            return "redirect:/login?error";
        }
    }
}