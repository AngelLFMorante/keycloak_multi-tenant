package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.ClientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para la gestión de Clientes de Keycloak.
 * <p>
 * Proporciona endpoints para la creación y futuras operaciones de administración de clientes.
 *
 * @author Angel Fm
 * @version 1.0
 */
@RestController
@RequestMapping("/api/v1/clients")
@Tag(name = "Gestión de Clientes", description = "Endpoints para la creación y administración de clientes.")
public class ClientController {

    private static final Logger log = LoggerFactory.getLogger(ClientController.class);
    private final ClientService clientService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param clientService El servicio que gestiona la lógica de negocio de los clientes.
     */
    public ClientController(ClientService clientService) {
        this.clientService = clientService;
        log.info("ClientController inicializado.");
    }

    /**
     * Crea un nuevo cliente confidencial en un realm de Keycloak.
     *
     * @param request La solicitud que contiene el nombre del cliente y el realm.
     * @return Una respuesta HTTP con el secreto del cliente y el estado 201 (CREATED).
     */
    @Operation(
            summary = "Crear un nuevo cliente",
            description = "Crea un nuevo cliente confidencial de Keycloak en un realm específico. Requiere un token de administración válido."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Cliente creado exitosamente. La respuesta contiene el client secret.",
                    content = @Content(
                            mediaType = "text/plain",
                            examples = @ExampleObject(
                                    value = "Cliente 'my-new-client' creado exitosamente. Client Secret: 'my-secret'"
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "La solicitud es incorrecta o los datos no son válidos.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "El realm especificado no fue encontrado.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "El cliente ya existe en el realm.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            )
    })
    @PostMapping("/create")
    public ResponseEntity<String> createClient(@Valid @RequestBody ClientCreationRequest request) {
        log.info("Recibida solicitud para crear un nuevo cliente: {}", request.clientName());
        String clientSecret = clientService.createClient(request);
        String successMessage = String.format("Cliente '%s' creado exitosamente. Client Secret: '%s'",
                request.clientName(), clientSecret);
        log.info(successMessage);
        return new ResponseEntity<>(successMessage, HttpStatus.CREATED);
    }
}
