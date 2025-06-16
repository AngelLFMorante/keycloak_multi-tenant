package com.example.keycloakdemo.services;

import jakarta.annotation.PostConstruct;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
public class KeycloakAdminService {

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    // Credenciales de administración para el realm 'master' (usadas para gestionar otros realms)
    @Value("${keycloak.admin.plexus.username}")
    private String plexusAdminUsername;
    @Value("${keycloak.admin.plexus.password}")
    private String plexusAdminPassword;
    @Value("${keycloak.admin.plexus.client-id}")
    private String plexusAdminClientId;

    // Mapa para almacenar los clientes Keycloak admin, mapeados por tenantId.
    // Aunque ahora solo tenemos "plexus", está listo para "inditex" más adelante.
    private Map<String, Keycloak> keycloakAdminClients = new HashMap<>();

    /**
     * Se ejecuta después de la inyección de dependencias.
     * Inicializa los clientes de administración de Keycloak para cada tenant configurado.
     */
    @PostConstruct
    public void init() {
        // Inicializa el cliente admin para el tenant "plexus".
        // Importante: El cliente se autentica en el realm "master" con las credenciales de un admin
        // que tiene permisos para gestionar el 'plexus-realm'.
        keycloakAdminClients.put("plexus", buildKeycloakAdminClient("master", plexusAdminUsername, plexusAdminPassword, plexusAdminClientId));
        // Cuando quieras añadir 'inditex', la línea descomentada iría aquí, usando sus propias credenciales de admin del master realm.
        // keycloakAdminClients.put("inditex", buildKeycloakAdminClient("master", inditexAdminUsername, inditexAdminPassword, inditexAdminClientId));
    }

    /**
     * Construye y devuelve una instancia de Keycloak Admin Client.
     * @param realm El realm en el que el cliente administrador se autenticará (normalmente "master").
     * @param username El nombre de usuario del administrador en ese realm.
     * @param password La contraseña del administrador.
     * @param clientId El Client ID para la autenticación (normalmente "admin-cli").
     * @return Una instancia de Keycloak Admin Client.
     */
    private Keycloak buildKeycloakAdminClient(String realm, String username, String password, String clientId) {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm(realm) // Se autentica en el realm 'master' para obtener permisos administrativos.
                .username(username)
                .password(password)
                .clientId(clientId)
                .grantType("password")
                .build();
    }

    /**
     * Crea un nuevo usuario en el realm especificado del tenant, lo marca como no verificado y establece una contraseña.
     * @param tenantId El ID del tenant (ej. "plexus", "inditex") que corresponde al realm en Keycloak (ej. "plexus-realm").
     * @param username El nombre de usuario del nuevo usuario.
     * @param email El email del nuevo usuario.
     * @param password La contraseña del nuevo usuario.
     * @return true si el usuario fue creado exitosamente, false si ya existe o hubo un error de otro tipo.
     */
    public boolean createUserInRealm(String tenantId, String username, String email, String password) {
        // Asegúrate de que el tenantId se mapea al nombre real del realm en Keycloak si son diferentes.
        // En tu caso, 'plexus' se mapea a 'plexus-realm' en el issuer-uri,
        // pero la API de admin usa el nombre del realm directamente.
        String keycloakRealmName = tenantId + "-realm"; // Asumiendo que tus realms son 'plexus-realm', 'inditex-realm' etc.

        Keycloak keycloakAdminClient = keycloakAdminClients.get(tenantId);
        if (keycloakAdminClient == null) {
            System.err.println("Keycloak admin client not found for tenant: " + tenantId + ". Check @PostConstruct configuration.");
            return false;
        }

        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true); // El usuario está habilitado al crearse.
        user.setUsername(username);
        user.setEmail(email);
        user.setEmailVerified(false); // Importante: marcado como no verificado inicialmente para la aprobación manual.

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false); // Contraseña no temporal.
        user.setCredentials(Collections.singletonList(credential));

        try {
            // Comprueba si el usuario ya existe para evitar errores y duplicados.
            if (!keycloakAdminClient.realm(keycloakRealmName).users().search(username, true).isEmpty()) { // <-- DESCOMENTA ESTA LÍNEA
                System.out.println("User '" + username + "' already exists in realm '" + keycloakRealmName + "'.");
                return false; // El usuario ya existe.
            }

            // Crea el usuario en el realm del tenant especificado.
            keycloakAdminClient.realm(keycloakRealmName).users().create(user);
            System.out.println("User '" + username + "' created successfully in realm '" + keycloakRealmName + "'. Waiting for admin approval.");
            return true;
        } catch (Exception e) {
            // Captura cualquier excepción durante la creación del usuario.
            System.err.println("Error creating user '" + username + "' in Keycloak realm '" + keycloakRealmName + "': " + e.getClass().getName() + " - " + e.getMessage()); // <-- He mejorado este log
            throw e; // Relanza la excepción para que el controlador la pueda manejar.
        }
    }

    /**
     * Comprueba si un usuario en un realm específico está verificado (aprobado).
     * @param tenantId El ID del tenant.
     * @param username El nombre de usuario.
     * @return true si el email del usuario está verificado, false en caso contrario.
     */
    public boolean isUserVerified(String tenantId, String username) {
        String keycloakRealmName = tenantId + "-realm"; // Mapea tenantId a nombre de realm.

        Keycloak keycloakAdminClient = keycloakAdminClients.get(tenantId);
        if (keycloakAdminClient == null) {
            System.err.println("Keycloak admin client not found for tenant: " + tenantId);
            return false;
        }
        try {
            UserRepresentation user = keycloakAdminClient.realm(keycloakRealmName).users().search(username, true).stream().findFirst().orElse(null);
            return user != null && user.isEmailVerified();
        } catch (Exception e) {
            System.err.println("Error checking user verification status for '" + username + "' in Keycloak realm '" + keycloakRealmName + "': " + e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene un token de acceso para un usuario dado en un realm específico.
     * Este método no se usa directamente en el flujo de registro que hemos estado desarrollando,
     * pero puede ser útil para otros propósitos (ej. inicio de sesión programático).
     * @param realm El nombre del realm (ej. "plexus-realm").
     * @param clientId El ID del cliente (ej. "mi-spring-app-plexus").
     * @param clientSecret El secreto del cliente.
     * @param username El nombre de usuario.
     * @param password La contraseña del usuario.
     * @return El token de acceso como String.
     * @throws RuntimeException si hay un error al obtener el token.
     */
    public String obtainToken(String realm, String clientId, String clientSecret, String username, String password) {
        String tokenUrl = keycloakBaseUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", username);
        body.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                return (String) response.getBody().get("access_token");
            } else {
                // Esta parte se ejecuta si Keycloak responde con un código de error (ej. 400, 401, 403)
                // y podremos ver el body del error de Keycloak.
                System.err.println("Error obteniendo token de Keycloak. HTTP Status: " + response.getStatusCode());
                System.err.println("Response Body: " + response.getBody());
                throw new RuntimeException("Error obteniendo token de Keycloak: " + response.getStatusCode() + " - " + response.getBody());
            }
        } catch (Exception e) {
            // Esta parte se ejecuta si la llamada a restTemplate.postForEntity() lanza una excepción
            // antes de recibir una respuesta válida de Keycloak (ej. problema de conexión, URL incorrecta, etc.)
            System.err.println("Excepción al intentar obtener token de Keycloak:");
            e.printStackTrace(); // <--- ¡Esto es lo que necesitamos ver!
            throw new RuntimeException("Error llamando a Keycloak para obtener token", e);
        }
    }
}