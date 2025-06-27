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
 * a una URL de inicio específica del tenant basada en el ID de registro de OAuth2.
 *
 * NOTA: Este manejador está diseñado principalmente para el flujo OAuth2 Login (Authorization Code Flow).
 * Para el flujo de Password Grant Type implementado en el LoginController, se usó
 * {@link org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler}.
 * Si la aplicación usa ambos flujos, es importante que cada flujo invoque el handler correcto.
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
     * y el tenant está mapeado. Si no se puede determinar un tenant o no es un token OAuth2,
     * redirige a la raíz del sitio ("/").
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

        // Verifica si el objeto de autenticación es una instancia de OAuth2AuthenticationToken.
        // Esto indica que el login se realizó a través del flujo OAuth2/OIDC de Spring Security.
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            // Obtiene el 'registrationId' (que representa el tenant o proveedor de identidad)
            // del cliente OAuth2 que fue utilizado para la autenticación.
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            System.out.println("Login exitoso para tenant (OAuth2): " + registrationId);

            // Verifica si el 'registrationId' obtenido de la autenticación OAuth2 existe
            // en el mapa de tenants predefinido.
            if (tenantMapping.containsKey(registrationId)) {
                // Si el tenant existe en el mapeo, construye la URL de redirección
                // utilizando el 'registrationId' como parte de la ruta base.
                response.sendRedirect("/" + registrationId + "/home");
                return; // Termina la ejecución del método después de la redirección.
            }
        }
        // Si la autenticación no es una instancia de OAuth2AuthenticationToken (ej. si es del flujo manual),
        // o si el 'registrationId' de OAuth2 no se encuentra en el mapeo,
        // se redirige a la URL raíz del sitio como fallback.
        // Esto puede ocurrir si se usa con un tipo de autenticación diferente o si el tenant no está mapeado.
        response.sendRedirect("/");
    }
}
