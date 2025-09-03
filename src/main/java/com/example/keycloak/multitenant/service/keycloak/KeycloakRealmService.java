package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio cliente para la administración de realms en Keycloak.
 * <p>
 * Se encarga de la lógica de negocio para interactuar con la API de administración
 * de Keycloak, delegando las operaciones de bajo nivel a {@link KeycloakAdminService}.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakRealmService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRealmService.class);
    private final KeycloakAdminService utilsAdminService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param utilsAdminService Servicio para operaciones administrativas de bajo nivel.
     */
    public KeycloakRealmService(KeycloakAdminService utilsAdminService) {
        this.utilsAdminService = utilsAdminService;
    }

    /**
     * Crea un nuevo realm en Keycloak si no existe.
     * <p>
     * Este método verifica la existencia del realm antes de proceder. Si el realm
     * ya existe, lanza una excepción de conflicto. Si no, crea el realm y
     * delega el manejo de errores HTTP al {@link com.example.keycloak.multitenant.config.GlobalExceptionHandler}.
     *
     * @param realmName El nombre del realm que se desea crear.
     * @throws ResponseStatusException            con estado CONFLICT si el realm ya existe.
     * @throws jakarta.ws.rs.ClientErrorException si hay un error 4xx del cliente de Keycloak.
     * @throws jakarta.ws.rs.ServerErrorException si hay un error 5xx del servidor de Keycloak.
     */
    public void createRealm(String realmName) {
        log.info("Verificando si el realm '{}' ya existe.", realmName);

        RealmRepresentation existingRealm = utilsAdminService.getRealm(realmName);
        if (existingRealm != null) {
            log.warn("El realm '{}' ya existe.", realmName);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El realm ya existe.");
        }

        log.info("El realm '{}' no existe. Procediendo a crearlo.", realmName);
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(realmName);
        realmRepresentation.setEnabled(true);

        RealmsResource realmsResource = utilsAdminService.realms();
        realmsResource.create(realmRepresentation);
        log.info("Realm '{}' creado con éxito.", realmName);
    }
}
