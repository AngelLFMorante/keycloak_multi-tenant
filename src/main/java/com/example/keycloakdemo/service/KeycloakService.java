package com.example.keycloakdemo.service;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
import com.example.keycloakdemo.model.RegisterRequest;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para interactuar con la API de administración de Keycloak.
 * Proporciona métodos para realizar operaciones administrativas, como la creación de usuarios,
 * en un realm específico de Keycloak.
 */
@Service
public class KeycloakService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakService.class);

    /**
     * Cliente de administración de Keycloak, inyectado automáticamente.
     * Este cliente se utiliza para realizar llamadas a la API REST de administración de Keycloak.
     */
    private final Keycloak keycloak;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloak Instancia del cliente de administración de Keycloak.
     */
    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
        log.info("KeycloakService inicializado.");
    }

    /**
     * Crea un nuevo usuario en un realm específico de Keycloak.
     * Después de la creación, se establece la contraseña del usuario.
     * Por defecto, el usuario se crea como deshabilitado, requiriendo aprobación del administrador.
     *
     * @param realm   El nombre del realm de Keycloak donde se creará el usuario (ej. "plexus-realm").
     * @param request Un objeto {@link RegisterRequest} que contiene los detalles del usuario a registrar.
     * @throws RuntimeException Si la creación del usuario o el establecimiento de la contraseña fallan en Keycloak.
     */
    public void createUser(String realm, RegisterRequest request) {
        log.info("Intentando crear usuario '{}' en el realm '{}'.", request.getUsername(), realm);
        log.debug("Datos de usuario para creación: username={}, email={}, firstName={}, lastName={}",
                request.getUsername(), request.getEmail(), request.getFirstName(), request.getLastName());

        // Crea una representación del usuario a partir de los datos de la solicitud de registro.
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEnabled(false); // Esto requiere que un administrador lo habilite manualmente en Keycloak.

        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();

        // Se obtiene una instancia del realm y luego se accede al recurso de usuarios para crear uno nuevo.
        try (Response response = usersResource.create(user)) {
            if (response.getStatus() == 201) {
                log.info("Usuario '{}' creado exitosamente en Keycloak. Status: 201 Created.", request.getUsername());

                // La cabecera Location contiene la URL del recurso del nuevo usuario (ej. /auth/admin/realms/{realm}/users/{userId}).
                // Se utiliza una expresión regular para extraer el 'userId' de esa URL.
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                log.debug("ID de usuario creado: {}", userId);

                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue(request.getPassword());
                credential.setTemporary(false);

                try {
                    // Se accede al recurso del usuario por su ID y se llama al metodo resetPassword.
                    realmResource.users().get(userId).resetPassword(credential);
                    log.info("Contraseña establecida exitosamente para el usuario '{}'.", request.getUsername());
                } catch (Exception e) {
                    log.error("Fallo al establecer la contraseña para el usuario '{}' (ID: {}). Error: {}", request.getUsername(), userId, e.getMessage(), e);
                    throw new KeycloakUserCreationException("Error al establecer la contraseña para el usuario '" + request.getUsername() + "': " + e.getMessage(), e);
                }
            } else {
                String errorDetails = response.readEntity(String.class);
                log.error("Fallo al crear usuario '{}' en Keycloak. Status: {}, Detalles: {}", request.getUsername(), response.getStatus(), errorDetails);
                throw new KeycloakUserCreationException("Error al crear usuario en Keycloak. Estado HTTP: " + response.getStatus() + ". Detalles: " + errorDetails);
            }
        }catch (KeycloakUserCreationException e){
            throw e;
        }catch (Exception e){
            log.error("Excepción inesperada al intentar crear usuario '{}'  en Keycloak : {}", request.getUsername(), realm);
            throw new KeycloakUserCreationException("Error inesperado al crear usuario: " + e.getMessage(), e);
        }
    }

    /**
     * Comprueba si un usuario con el email dado ya existe en Keycloak
     * @param realm El nombre del realm de Keycloak a consultar
     * @param email El email a buscar
     * @return true si el email existe en Keycloak
     */
    public boolean userExistsByEmail(String realm, String email){
        log.debug("Comprobando si el email '{}' ya existe en el realm '{}'.", email, realm);
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource userResource = realmResource.users();

        List<UserRepresentation> users = userResource.searchByEmail(email, true);

        if( users != null && !users.isEmpty()){
            log.info("Email '{}' ya existe en el realm '{}'.", email, realm);
            return true;
        }else{
            log.debug("Email '{}' no encontrado en el realm '{}'.", email, realm);
            return false;
        }
    }
}
