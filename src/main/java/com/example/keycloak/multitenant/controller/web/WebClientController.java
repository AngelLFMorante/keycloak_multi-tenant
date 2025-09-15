package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.ClientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controlador web para la gestión de clientes en un realm específico.
 * <p>
 * Este controlador proporciona endpoints para renderizar páginas web y procesar
 * formularios relacionados con la creación de clientes de Keycloak.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Controller
@RequestMapping("/{realm}/clients")
@Tag(name = "Client Web", description = "Endpoints web para la gestión de clientes en un realm.")
public class WebClientController {

    private static final Logger log = LoggerFactory.getLogger(WebClientController.class);
    private final ClientService clientService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param clientService Servicio que maneja la lógica de negocio para los clientes.
     */
    public WebClientController(ClientService clientService) {
        this.clientService = clientService;
        log.info("WebClientController inicializado.");
    }

    /**
     * Muestra el formulario para crear un nuevo cliente para un realm dado.
     *
     * @param realm El nombre del realm (tenant) donde se creará el cliente.
     * @param model El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista ("create-client") que contiene el formulario.
     */
    @Operation(
            summary = "Muestra el formulario para crear un cliente.",
            description = "Renderiza la página web con el formulario de creación de cliente para un realm específico."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Formulario renderizado exitosamente.")
    })
    @GetMapping("/create")
    public String showCreateClientForm(
            @Parameter(description = "El nombre del realm (tenant).", required = true)
            @PathVariable String realm,
            Model model) {
        log.info("Mostrando formulario para crear cliente en el realm: {}", realm);
        model.addAttribute("realm", realm);
        return "create-client";
    }

    /**
     * Procesa el envío del formulario para crear un nuevo cliente en Keycloak.
     * <p>
     * Se crea un cliente con el nombre proporcionado y, si tiene éxito, el secreto del cliente
     * se pasa al modelo para su visualización. En caso de error, se añade un mensaje de error al modelo.
     *
     * @param realm      El nombre del realm (tenant) donde se creará el cliente.
     * @param clientName El nombre del cliente a crear.
     * @param model      El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista del formulario ("create-client") con un mensaje de éxito o error.
     */
    @Operation(
            summary = "Procesa la creación de un nuevo cliente.",
            description = "Recibe el nombre del cliente del formulario y lo crea en Keycloak. El secreto del cliente se devuelve para su visualización."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Cliente creado con éxito. Devuelve la misma página con un mensaje de éxito."),
            @ApiResponse(responseCode = "400", description = "Error al crear el cliente. Devuelve la misma página con un mensaje de error.")
    })
    @PostMapping("/create")
    public String createClient(
            @Parameter(description = "El nombre del realm (tenant).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El nombre del cliente a crear.", required = true)
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
