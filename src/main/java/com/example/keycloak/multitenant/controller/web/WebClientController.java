package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.ClientService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controlador web para la gestión de clientes.
 * Proporciona endpoints para renderizar páginas de creación de clientes.
 */
@Controller
@RequestMapping("/{realm}/clients")
public class WebClientController {

    private static final Logger log = LoggerFactory.getLogger(WebClientController.class);
    private final ClientService clientService;

    public WebClientController(ClientService clientService) {
        this.clientService = clientService;
        log.info("WebClientController inicializado.");
    }

    /**
     * Muestra el formulario para crear un nuevo cliente.
     *
     * @param realm El realm donde se creará el cliente.
     * @param model El modelo para pasar datos a la vista.
     * @return La vista del formulario de creación de cliente.
     */
    @GetMapping("/create")
    public String showCreateClientForm(@PathVariable String realm, Model model) {
        log.info("Mostrando formulario para crear cliente en el realm: {}", realm);
        model.addAttribute("realm", realm);
        return "create-client";
    }

    /**
     * Procesa el formulario para crear un nuevo cliente.
     *
     * @param realm      El realm donde se creará el cliente.
     * @param clientName El nombre del cliente a crear.
     * @param model      El modelo para pasar datos a la vista.
     * @return La vista del formulario con un mensaje de éxito o error.
     */
    @PostMapping("/create")
    public String createClient(@PathVariable String realm,
                               @RequestParam String clientName,
                               Model model) {
        log.info("Procesando solicitud web para crear un cliente: {} en el realm: {}", clientName, realm);
        try {
            ClientCreationRequest request = new ClientCreationRequest(realm, clientName);
            String clientSecret = clientService.createClient(request);
            model.addAttribute("message", "¡Cliente creado exitosamente!");
            model.addAttribute("realm", realm);
            model.addAttribute("clientSecret", clientSecret);
        } catch (Exception e) {
            log.error("Error al crear el cliente: {}", e.getMessage());
            model.addAttribute("error", "Error al crear el cliente: " + e.getMessage());
            model.addAttribute("realm", realm);
        }
        return "create-client";
    }
}
