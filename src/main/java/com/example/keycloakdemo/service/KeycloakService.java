package com.example.keycloakdemo.service;

import com.example.keycloakdemo.model.RegisterRequest;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.springframework.stereotype.Service;

/**
 * Servicio para interactuar con la API de administración de Keycloak.
 * Proporciona métodos para realizar operaciones administrativas, como la creación de usuarios,
 * en un realm específico de Keycloak.
 */
@Service
public class KeycloakService {

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
        // 1. Crear una representación del usuario a partir de los datos de la solicitud de registro.
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());     // Establece el nombre de usuario.
        user.setEmail(request.getEmail());           // Establece el email del usuario.
        user.setFirstName(request.getFirstName());   // Establece el primer nombre.
        user.setLastName(request.getLastName());     // Establece el apellido.
        user.setEnabled(false);                      // Por defecto, el usuario está deshabilitado.
        // Esto requiere que un administrador lo habilite manualmente en Keycloak.

        // 2. Enviar la solicitud para crear el usuario en Keycloak.
        // Se obtiene una instancia del realm y luego se accede al recurso de usuarios para crear uno nuevo.
        Response response = keycloak.realm(realm).users().create(user);

        // 3. Verificar el estado de la respuesta.
        // Un estado 201 (Created) indica que el usuario fue creado exitosamente.
        if (response.getStatus() != 201) {
            // Si el estado no es 201, se lanza una excepción indicando el error.
            throw new RuntimeException("Error creating user: " + response.getStatus());
        }

        // 4. Extraer el ID del usuario recién creado de la cabecera 'Location' de la respuesta.
        // La cabecera Location contiene la URL del recurso del nuevo usuario (ej. /auth/admin/realms/{realm}/users/{userId}).
        // Se utiliza una expresión regular para extraer el 'userId' de esa URL.
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

        // 5. Crear una representación de la credencial (contraseña) para el usuario.
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD); // Indica que es una credencial de tipo contraseña.
        credential.setValue(request.getPassword()); // Establece el valor de la contraseña.
        credential.setTemporary(false);             // La contraseña no será temporal, el usuario no necesitará cambiarla al primer login.

        // 6. Restablecer/establecer la contraseña del usuario recién creado.
        // Se accede al recurso del usuario por su ID y se llama al método resetPassword.
        keycloak.realm(realm).users().get(userId).resetPassword(credential);
    }
}
