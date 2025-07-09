package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.model.RegisterRequest;
import com.example.keycloakdemo.service.KeycloakService;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static Logger log = LoggerFactory.getLogger(RegisterController.class);
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
        log.info("RegisterController inicializado.");
    }

    /**
     * Maneja las solicitudes GET para informar sobre el endpoint de registro de un tenant específico.
     *
     * @param realm El nombre del realm (tenant) para el cual se va a registrar el usuario.
     * @return El nombre de la vista ("register") que contiene el formulario de registro.
     */
    @GetMapping("/{realm}/register")
    public ResponseEntity<Map<String,Object>> showRegisterForm(@PathVariable String realm) {
        log.info("Solicitud GET para información de registro del tenant: {}", realm);
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
        log.info("Intento de registro de usuario para el tenant: {}", realm);
        log.debug("Datos de registro recibidos: username={}, email={}", request.getUsername(), request.getEmail());

        // Verifica si las contraseñas no coinciden.
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            log.warn("Error de registro: Las contraseñas no coinciden para el usuario '{}'.", request.getUsername());
            throw new IllegalArgumentException("Password no coinciden");
        }

        //Comprobar si el email existe en keycloak
        if(keycloakService.userExistsByEmail(singleKeycloakRealm, request.getEmail())){
            log.warn("Error de registro: El email'{}' ya esta registrado en el realm '{}'.", request.getEmail(), realm);
            throw new IllegalArgumentException(("El email '" + request.getEmail() + "' ya está registrado en Keycloak."));
        }

        // Esto es crucial para que la llamada al servicio de Keycloak sea correcta.
        keycloakService.createUser(realm, request); // Delega la creación del usuario a KeycloakService.
        log.info("Usuario '{}' registrado exitosamente en el realm Keycloak '{}' para el tenant '{}'.", request.getUsername(), singleKeycloakRealm, realm);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User registered. Waiting for admin approval."); // Mensaje de éxito.
        response.put("tenantId", realm); // Añade el ID del tenant al modelo.
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
