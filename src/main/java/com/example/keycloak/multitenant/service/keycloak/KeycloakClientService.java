package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de cliente de administración de Keycloak que gestiona las
 * operaciones del lado del servidor para los realms, usuarios y clientes.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakClientService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClientService.class);
    private final KeycloakAdminService keycloakAdminService;

    public KeycloakClientService(KeycloakAdminService keycloakAdminService) {
        this.keycloakAdminService = keycloakAdminService;
        log.info("Servicio de cliente de administración de Keycloak inicializado.");
    }

    /**
     * Crea un nuevo cliente confidencial en un realm específico.
     * <p>
     * Se configura un nuevo cliente con credenciales de cliente (client secret).
     *
     * @param realmName El nombre del realm donde se creará el cliente.
     * @param clientId  El ID del cliente a crear.
     * @return El client secret generado para el nuevo cliente.
     * @throws ClientErrorException si el cliente ya existe o hay un error de validación.
     */
    public String createClient(String realmName, String clientId) {
        log.info("Iniciando la creación del cliente '{}' en el realm '{}'.", clientId, realmName);
        RealmResource realmResource = keycloakAdminService.getRealmResource(realmName);

        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(clientId);
        clientRepresentation.setEnabled(true);
        clientRepresentation.setPublicClient(false);
        clientRepresentation.setStandardFlowEnabled(true);
        clientRepresentation.setClientAuthenticatorType("client-secret");
        clientRepresentation.setServiceAccountsEnabled(true);
        clientRepresentation.setDirectAccessGrantsEnabled(true);

        Response response = realmResource.clients().create(clientRepresentation);

        if (response.getStatus() != 201) {
            log.error("Error al crear el cliente '{}'. Código de estado: {}", clientId, response.getStatus());
            throw new ClientErrorException("Fallo al crear el cliente", Response.Status.fromStatusCode(response.getStatus()));
        }

        String createdClientId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        log.info("Cliente '{}' creado con ID interno: {}.", clientId, createdClientId);

        RealmResource realm = keycloakAdminService.getRealmResource(realmName);
        CredentialRepresentation clientSecret = realm.clients().get(createdClientId)
                .getSecret();

        log.info("Client '{}' creado con éxito. Client Secret: '{}'", clientId, clientSecret.getValue());
        return clientSecret.getValue();
    }
}
