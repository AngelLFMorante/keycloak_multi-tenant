package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.RealmCreationRequest;
import com.example.keycloak.multitenant.service.RealmService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para la gestión de Realms en Keycloak.
 * <p>
 * Proporciona endpoints para la creación y futuras operaciones de administración de realms.
 *
 * @author Angel Fm
 * @version 1.0
 */
@RestController
@RequestMapping("/api/v1/realms")
@Tag(name = "Gestión de Realms", description = "Endpoints para la creación y administración de realms.")
public class RealmController {

    private static final Logger log = LoggerFactory.getLogger(RealmController.class);
    private final RealmService realmService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param realmService El servicio que gestiona la lógica de negocio de los realms.
     */
    @Autowired
    public RealmController(RealmService realmService) {
        this.realmService = realmService;
        log.info("RealmController inicializado.");
    }

    /**
     * Crea un nuevo realm en Keycloak.
     * <p>
     * Este endpoint recibe una solicitud JSON con el nombre del realm a crear.
     *
     * @param request La solicitud que contiene el nombre del nuevo realm. El cuerpo de la solicitud se valida
     *                automáticamente.
     * @return Una respuesta HTTP con un mensaje de éxito y el estado 201 (CREATED).
     */
    @Operation(
            summary = "Crear un nuevo realm",
            description = "Crea un nuevo realm de Keycloak con la configuración por defecto. Requiere un token de administración válido."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Realm creado exitosamente.",
                    content = @Content(
                            mediaType = "text/plain",
                            examples = @ExampleObject(
                                    value = "Realm 'nuevo-realm-de-prueba' creado exitosamente."
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "El nombre del realm no es valido o la solicitud es incorrecta.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "El realm ya existe.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Error interno del servidor.",
                    content = @Content(
                            mediaType = "application/json"
                    )
            )
    })
    @PostMapping("/create")
    public ResponseEntity<String> createRealm(@Valid @RequestBody RealmCreationRequest request) {
        log.info("Recibida solicitud para crear un nuevo realm: {}", request.realmName());
        realmService.createRealm(request);
        String successMessage = "Realm '" + request.realmName() + "' creado exitosamente.";
        log.info(successMessage);
        return new ResponseEntity<>(successMessage, HttpStatus.CREATED);
    }
}
