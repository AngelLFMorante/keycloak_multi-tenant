package com.example.keycloakdemo.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Manejador de éxito de autenticación personalizado para Spring Security.
 * Implementa {@link AuthenticationSuccessHandler} para definir el comportamiento
 * después de que un usuario se ha autenticado exitosamente.
 * Este manejador está diseñado para aplicaciones multi-tenant, redirigiendo al usuario
 * a una URL de inicio específica del tenant basada en el ID de registro de OAuth2
 * o extrayendo el tenant de la URL de la solicitud para flujos de login manual.
 *
 * NOTA: Este manejador está diseñado para soportar tanto el flujo OAuth2 Login
 * (Authorization Code Flow) como el flujo de Password Grant Type implementado
 * manualmente (por ejemplo, en un LoginController).
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    /**
     * Mapeo de tenants a la información de su realm y client ID.
     * La clave del mapa es el 'registrationId' (nombre del tenant/ID de registro en Spring Security).
     * El valor es un array de String: [0] -> nombre del realm en Keycloak, [1] -> client ID en Keycloak.
     * Ejemplo: "plexus" -> ["plexus-realm", "mi-app-plexus"]
     * Este mapeo se utiliza para determinar la URL de redirección específica del tenant.
     */
    private final Map<String, String[]> tenantMapping = Map.of(
            "plexus", new String[]{"plexus-realm", "mi-app-plexus"},
            "inditex", new String[]{"inditex-realm", "mi-app-inditex"}
    );

    /**
     * Este metodo es invocado por Spring Security después de una autenticación exitosa.
     * Su principal función es redirigir al usuario a la página de inicio específica
     * del tenant (`/{tenant}/home`) si la autenticación se realizó a través de OAuth2 Login
     * o si el tenant puede ser extraído de la URL de la solicitud para el login manual.
     * Si no se puede determinar un tenant o no está mapeado, redirige a la raíz del sitio ("/").
     *
     * @param request        La solicitud HTTP que originó la autenticación.
     * @param response       La respuesta HTTP a la que se le puede añadir la redirección.
     * @param authentication El objeto Authentication que representa al usuario autenticado,
     * incluyendo sus principales, credenciales y autoridades.
     * @throws IOException      Si ocurre un error de entrada/salida durante la redirección.
     * @throws ServletException Si ocurre un error específico del servlet.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String tenantId = null;

        // 1. Intenta obtener el tenant del token OAuth2 (si el login fue por OAuth2 Login)
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            tenantId = oauthToken.getAuthorizedClientRegistrationId();
            System.out.println("Login exitoso para tenant (OAuth2): " + tenantId);
        } else {
            // 2. Si no es un token OAuth2, intenta extraer el tenant de la URL de la solicitud.
            // Esto es crucial para el flujo de login manual (Password Grant Type)
            // asumiendo que la URL de POST de login es /{tenant}/do_login.
            tenantId = extractTenantFromRequestUri(request);
            System.out.println("Login exitoso (manual), intentando extraer tenant de URI: " + tenantId);
        }

        // 3. Si se encontró un tenant y está mapeado, redirige a la URL específica del tenant.
        if (tenantId != null && tenantMapping.containsKey(tenantId)) {
            response.sendRedirect("/" + tenantId + "/home");
            return; // Termina la ejecución del método después de la redirección.
        }

        // 4. Si no se pudo determinar un tenant válido o no está mapeado, redirige a la raíz del sitio como fallback.
        response.sendRedirect("/");
    }

    /**
     * Extrae el ID del tenant de la URI de la solicitud HTTP.
     * Asume un patrón de URL como "/{tenant}/do_login" o similar.
     *
     * @param request La solicitud HTTP.
     * @return El ID del tenant si se encuentra, de lo contrario, null.
     */
    private String extractTenantFromRequestUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        // Ejemplo: /plexus/do_login
        // Dividimos la URI por el carácter '/'
        String[] parts = requestUri.split("/");
        // Buscamos la primera parte no vacía después del primer '/' que no sea "do_login"
        if (parts.length > 1) {
            for (int i = 1; i < parts.length; i++) {
                // Aseguramos que la parte no esté vacía y no sea el nombre del endpoint de login
                if (!parts[i].isEmpty() && !parts[i].equals("do_login") && !parts[i].equals("register")) {
                    return parts[i];
                }
            }
        }
        return null; // No se pudo extraer el tenant
    }
}
