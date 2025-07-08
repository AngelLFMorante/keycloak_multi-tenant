package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.model.RegisterRequest;
import com.example.keycloakdemo.service.KeycloakService;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para gestionar el proceso de registro de nuevos usuarios en Keycloak.
 * Maneja la visualización del formulario de registro y el procesamiento de la solicitud de registro.
 * La creación de usuarios en Keycloak se delega a {@link KeycloakService}.
 */
@RestController
public class RegisterController {

    /**
     * Servicio que interactúa con la API de administración de Keycloak para operaciones relacionadas con usuarios.
     */
    private final KeycloakService keycloakService;

    /**
     * El nombre del único realm de keycloak que se utilizara para todas las operaciones.
     * Este valor se inyectará desde las propiedades de la aplicación
     */
    @Value("keycloak.single-realm-name")
    private String singleKeycloakRealm;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakService El servicio {@link KeycloakService} para interactuar con Keycloak.
     */
    public RegisterController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    /**
     * Maneja las solicitudes GET para informar sobre el endpoint de registro de un tenant específico.
     *
     * @param realm El nombre del realm (tenant) para el cual se va a registrar el usuario.
     * @return El nombre de la vista ("register") que contiene el formulario de registro.
     */
    @GetMapping("/{realm}/register")
    public ResponseEntity<Map<String,Object>> showRegisterForm(@PathVariable String realm) {
        Map<String, Object> response = new HashMap<>();
        response.put("realm", realm); // Añade el nombre del realm al modelo.
        response.put("registerRequest", new RegisterRequest()); // Añade un objeto vacío para el formulario.
        return ResponseEntity.ok(response);
    }

    /**
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * Recibe los datos de registro como JSON en el cuerpo de la solicitud.
     * Realiza una validación básica de contraseñas y luego delega la creación del usuario
     * a {@link KeycloakService}. Devuelve JSON con el estado de la operación.
     *
     * Importante: Ahora utiliza el `singleKeycloakRealm` inyectado para la creación del usuario,
     * en lugar de construirlo a partir del PathVariable.
     *
     * @param realm   El nombre del tenant extraído de la URL. Este `realm`
     * se usará para cualquier lógica específica del cliente si fuera necesario,
     * pero el registro de usuario se hace en el `singleKeycloakRealm` principal.
     * @param request El objeto {@link RegisterRequest} que contiene los datos del formulario de registro,
     * recibido del cuerpo de la solicitud JSON.
     * @return Un {@link ResponseEntity} con el estado de éxito o error del registro.
     */
    @PostMapping("/{realm}/register")
    public ResponseEntity<Map<String, Object>> register(@PathVariable String realm, @RequestBody RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        // Verifica si las contraseñas no coinciden.
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            response.put("error", "Passwords do not match"); // Añade mensaje de error al modelo.
            return ResponseEntity.badRequest().body(response);
        }

        try {
            // Concatena "-realm" al nombre del realm para formar el nombre completo del realm de Keycloak.
            // Esto es crucial para que la llamada al servicio de Keycloak sea correcta.
            keycloakService.createUser(realm, request); // Delega la creación del usuario a KeycloakService.

            response.put("message", "User registered. Waiting for admin approval."); // Mensaje de éxito.
            response.put("tenantId", realm); // Añade el ID del tenant al modelo.
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            // Captura cualquier excepción que ocurra durante el registro.
            response.put("error", "Registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
