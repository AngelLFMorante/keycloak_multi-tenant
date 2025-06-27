package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.model.RegisterRequest;
import com.example.keycloakdemo.service.KeycloakService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Controlador para gestionar el proceso de registro de nuevos usuarios en Keycloak.
 * Maneja la visualización del formulario de registro y el procesamiento de la solicitud de registro.
 * La creación de usuarios en Keycloak se delega a {@link KeycloakService}.
 */
@Controller
public class RegisterController {

    /**
     * Servicio que interactúa con la API de administración de Keycloak para operaciones relacionadas con usuarios.
     */
    private final KeycloakService keycloakService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakService El servicio {@link KeycloakService} para interactuar con Keycloak.
     */
    public RegisterController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    /**
     * Maneja las solicitudes GET para mostrar el formulario de registro de un tenant específico.
     * Añade el nombre del realm al modelo y una nueva instancia de {@link RegisterRequest}
     * para el enlace de datos del formulario.
     *
     * @param realm El nombre del realm (tenant) para el cual se va a registrar el usuario.
     * @param model El objeto {@link Model} para pasar datos a la vista.
     * @return El nombre de la vista ("register") que contiene el formulario de registro.
     */
    @GetMapping("/{realm}/register")
    public String showRegisterForm(@PathVariable String realm, Model model) {
        model.addAttribute("realm", realm); // Añade el nombre del realm al modelo.
        model.addAttribute("registerRequest", new RegisterRequest()); // Añade un objeto vacío para el formulario.
        return "register"; // Retorna el nombre de la vista "register.html".
    }

    /**
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * Realiza una validación básica de contraseñas y luego delega la creación del usuario
     * a {@link KeycloakService}.
     *
     * @param realm   El nombre del realm (tenant) en el que se registrará el usuario.
     * @param request El objeto {@link RegisterRequest} que contiene los datos del formulario de registro.
     * @param model   El objeto {@link Model} para añadir mensajes de éxito o error a la vista.
     * @return El nombre de la vista a la que redirigir ("login" en caso de éxito, "register" en caso de error).
     */
    @PostMapping("/{realm}/register")
    public String register(@PathVariable String realm, @ModelAttribute RegisterRequest request, Model model) {
        // Verifica si las contraseñas no coinciden.
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            model.addAttribute("error", "Passwords do not match"); // Añade mensaje de error al modelo.
            return "register"; // Retorna a la misma vista de registro con el error.
        }

        try {
            // Concatena "-realm" al nombre del realm para formar el nombre completo del realm de Keycloak.
            // Esto es crucial para que la llamada al servicio de Keycloak sea correcta.
            String keycloakRealm = realm.concat("-realm");
            keycloakService.createUser(keycloakRealm, request); // Delega la creación del usuario a KeycloakService.

            model.addAttribute("message", "User registered. Waiting for admin approval."); // Mensaje de éxito.
            model.addAttribute("tenantId", realm); // Añade el ID del tenant al modelo.
            return "login"; // Redirige a la vista de login para que el usuario pueda intentar iniciar sesión.
        } catch (Exception e) {
            // Captura cualquier excepción que ocurra durante el registro.
            model.addAttribute("error", "Registration failed: " + e.getMessage()); // Añade mensaje de error.
            return "register"; // Retorna a la vista de registro con el mensaje de error.
        }
    }
}
