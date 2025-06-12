package com.example.keycloakdemo.util;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;

public class KeycloakTokenTester {

    // --- Configuración de Keycloak ---
    // ASEGÚRATE de que estos valores son EXACTAMENTE los mismos que en tu application.properties
    private static final String KEYCLOAK_BASE_URL = "http://localhost:8080";
    private static final String MASTER_REALM_NAME = "master"; // El realm donde se autentica el admin
    private static final String ADMIN_USERNAME = "admin-plexus";
    private static final String ADMIN_PASSWORD = "password-plexus"; // <<<--- ¡REVISA MUY BIEN ESTA CONTRASEÑA!
    private static final String ADMIN_CLIENT_ID = "admin-cli"; // El cliente para operaciones de admin

    public static void main(String[] args) {
        System.out.println("Intentando obtener token de administración para Keycloak...");
        System.out.println("Base URL: " + KEYCLOAK_BASE_URL);
        System.out.println("Realm de autenticación: " + MASTER_REALM_NAME);
        System.out.println("Usuario: " + ADMIN_USERNAME);
        System.out.println("Client ID: " + ADMIN_CLIENT_ID);
        System.out.println("Contraseña: (no se muestra por seguridad, pero está en el código)");

        Keycloak keycloak = null;
        try {
            // Construye el cliente Keycloak Admin
            keycloak = KeycloakBuilder.builder()
                    .serverUrl(KEYCLOAK_BASE_URL)
                    .realm(MASTER_REALM_NAME)
                    .username(ADMIN_USERNAME)
                    .password(ADMIN_PASSWORD)
                    .clientId(ADMIN_CLIENT_ID)
                    .grantType("password") // Se usa grant_type "password" para este tipo de autenticación
                    .build();

            // Intenta obtener el token de acceso
            AccessTokenResponse tokenResponse = keycloak.tokenManager().getAccessToken(); // Esta línea es la que falla con 401

            System.out.println("\n--- ¡TOKEN OBTENIDO EXITOSAMENTE! ---");
            System.out.println("Access Token: " + tokenResponse.getToken().substring(0, 30) + "..."); // Mostrar solo una parte
            System.out.println("Refresh Token: " + (tokenResponse.getRefreshToken() != null ? tokenResponse.getRefreshToken().substring(0, 30) + "..." : "N/A"));
            System.out.println("Expires In: " + tokenResponse.getExpiresIn() + " seconds");
            System.out.println("Token Type: " + tokenResponse.getTokenType());

        } catch (jakarta.ws.rs.NotAuthorizedException e) {
            System.err.println("\n--- ERROR DE AUTORIZACIÓN (HTTP 401 Unauthorized) ---");
            System.err.println("Mensaje: " + e.getMessage());
            System.err.println("Causa posible: Credenciales incorrectas (usuario/contraseña) o Client ID incorrecto.");
            System.err.println("Asegúrate de que 'admin-plexus' exista en el realm 'master' y tenga la contraseña correcta.");
        } catch (Exception e) {
            System.err.println("\n--- OCURRIÓ UN ERROR INESPERADO ---");
            System.err.println("Tipo de error: " + e.getClass().getName());
            System.err.println("Mensaje: " + e.getMessage());
            e.printStackTrace(); // Imprime el stack trace completo para más detalles
        } finally {
            if (keycloak != null) {
                keycloak.close(); // Cierra el cliente Keycloak para liberar recursos
            }
        }
    }
}
