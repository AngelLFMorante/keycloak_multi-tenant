package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.dto.UserRegistrationForm; // Asegúrate de que esta ruta sea correcta
import com.example.keycloakdemo.services.KeycloakAdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam; // Necesario si mantienes el 'params' en @GetMapping /pending
import org.springframework.web.servlet.mvc.support.RedirectAttributes; // Para FlashAttributes

import jakarta.validation.Valid; // Para la validación del DTO

@Controller
public class RegistrationController {

    @Autowired
    private KeycloakAdminService keycloakAdminService;

    /**
     * Muestra el formulario de registro.
     * Añade un objeto UserRegistrationForm vacío al modelo para que Thymeleaf pueda vincular los campos.
     */
    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("userRegistrationForm", new UserRegistrationForm());
        model.addAttribute("tenantId", "plexus"); // Añadido para el título y el enlace de inicio de sesión
        return "register";
    }

    /**
     * Procesa la solicitud de registro enviada desde el formulario.
     * Realiza validaciones y crea el usuario en Keycloak.
     */
    @PostMapping("/plexus/process_register")
    public String processRegister(@ModelAttribute("userRegistrationForm") @Valid UserRegistrationForm registrationForm,
                                  BindingResult bindingResult,
                                  RedirectAttributes redirectAttributes) {

        // 1. Validación de Spring (@Valid en UserRegistrationForm)
        //    Spring llenará automáticamente 'bindingResult' con los errores de @NotBlank, @Email, @Size.

        // 2. Validación de contraseñas (lógica de negocio específica)
        //    Asegúrate de que la contraseña y la confirmación coincidan.
        if (registrationForm.getPassword() != null && !registrationForm.getPassword().equals(registrationForm.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "Las contraseñas no coinciden.");
        }

        // 3. Comprueba si hay errores de validación
        if (bindingResult.hasErrors()) {
            // Si hay errores, vuelve a la página de registro para mostrarlos
            // Los errores en 'bindingResult' estarán disponibles en la vista.
            return "register";
        }

        // 4. Procede con el registro del usuario en Keycloak
        //    Asegúrate de pasar la contraseña del formulario.
        boolean created = keycloakAdminService.createUserInRealm("plexus",
                registrationForm.getUsername(),
                registrationForm.getEmail(),
                registrationForm.getPassword());

        if (created) {
            // Si el usuario fue creado exitosamente:
            // Usa FlashAttributes para pasar datos a la siguiente redirección de forma segura (no en la URL).
            redirectAttributes.addFlashAttribute("username", registrationForm.getUsername());
            redirectAttributes.addFlashAttribute("tenantId", "plexus"); // Pasa también el tenantId si lo necesitas en la página de pendiente
            return "redirect:/pending?from=registration"; // Redirige a la página de pendiente de aprobación
        } else {
            // Si el registro falla (por ejemplo, usuario ya existe):
            // Añade un error global o específico al campo username para mostrarlo en la vista.
            bindingResult.rejectValue("username", "username.exists", "El nombre de usuario o email ya está registrado.");
            return "register"; // Vuelve a la página de registro con el mensaje de error.
        }
    }

    /**
     * Muestra la página de "pendiente de aprobación".
     * Este método solo se activa si la solicitud GET a /pending incluye el parámetro 'from=registration'.
     * Los datos pasados via FlashAttributes (username, tenantId) estarán disponibles en el modelo.
     */
    @GetMapping(value = "/pending", params = "from=registration")
    public String pendingApproval(Model model,
                                  @ModelAttribute("username") String username,
                                  @ModelAttribute("tenantId") String tenantId) {

        if (username == null) {
            username = "null";
        }
        if (tenantId == null) {
            tenantId = "tenant_null";
        }

        model.addAttribute("username", username);
        model.addAttribute("tenantId", tenantId);
        return "pending_approval";
    }
}