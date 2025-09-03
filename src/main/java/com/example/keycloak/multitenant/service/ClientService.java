package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.ClientCreationRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para la gestión de clientes en Keycloak.
 * <p>
 * Actúa como una capa de servicio que delega las operaciones administrativas
 * de creación de clientes al servicio de administración de Keycloak.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class ClientService {

    private static final Logger log = LoggerFactory.getLogger(ClientService.class);
    private final KeycloakClientService keycloakClientService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakClientService El servicio de cliente de administración de Keycloak.
     */
    public ClientService(KeycloakClientService keycloakClientService) {
        this.keycloakClientService = keycloakClientService;
        log.info("Servicio ClientService inicializado.");
    }

    /**
     * Crea un nuevo cliente en un realm específico de Keycloak.
     * <p>
     * Este método recibe una solicitud de creación, extrae los datos y delega la operación
     * al servicio de Keycloak.
     *
     * @param request El objeto de solicitud que contiene los detalles del cliente a crear.
     * @return El secreto del cliente recién creado.
     */
    public String createClient(ClientCreationRequest request) {
        log.info("Recibida solicitud de servicio para crear el cliente '{}' en el realm '{}'.",
                request.clientName(), request.realmName());
        String clientSecret = keycloakClientService.createClient(request.realmName(), request.clientName());
        log.info("Cliente '{}' creado con éxito en el realm '{}'.", request.clientName(), request.realmName());
        return clientSecret;
    }
}
