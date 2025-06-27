package com.example.keycloakdemo.repository;

import com.example.keycloakdemo.model.TenantInfo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Repositorio personalizado de {@link ClientRegistration} que permite la configuración
 * dinámica de clientes OAuth2 en función del tenant (inquilino) detectado a partir
 * de la URL de la solicitud HTTP actual.
 * <p>
 * Esta implementación es fundamental para aplicaciones multi-tenant donde cada inquilino
 * puede estar asociado con un Realm diferente en Keycloak y, por lo tanto,
 * requiere una configuración de cliente OAuth2 específica (realm, client ID, client secret, etc.).
 * <p>
 * Extiende {@link ClientRegistrationRepository} para ser compatible con el mecanismo
 * de carga de clientes de Spring Security OAuth2.
 */
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    /**
     * Caché concurrente para almacenar las configuraciones de clientes {@link ClientRegistration}
     * que ya han sido creadas. Esto evita regenerar la misma configuración para el mismo tenant
     * en cada solicitud, mejorando el rendimiento.
     * La clave del mapa es el segmento de path del tenant (ej. "plexus", "inditex").
     */
    private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();

    /**
     * URL base del servidor de autenticación de Keycloak.
     * Necesaria para construir las URIs completas de autenticación, tokens, etc.
     */
    private final String keycloakAuthServerUrl;

    /**
     * Configuración base de {@link ClientRegistration} de la cual se derivarán
     * las configuraciones dinámicas específicas de cada tenant.
     * Contiene valores comunes como el grant type, client authentication method, etc.
     */
    private final ClientRegistration baseClientRegistration;

    /**
     * Mapeo entre el segmento de path del tenant (ej. "plexus") y la información
     * detallada de su configuración en Keycloak (realm, clientId, clientSecret).
     * Esta información es estática y se define al inicializar el repositorio.
     */
    private final Map<String, TenantInfo> tenantMapping = new HashMap<>();

    /**
     * Constructor principal del repositorio de registro de clientes dinámico.
     * Inicializa la URL del servidor Keycloak, la configuración base del cliente
     * y el mapeo estático de los tenants conocidos con sus respectivas configuraciones.
     *
     * @param keycloakAuthServerUrl  URL base del servidor de autenticación de Keycloak.
     * @param baseClientRegistration Configuración base del cliente desde la cual se construirán
     * las configuraciones dinámicas.
     */
    public DynamicClientRegistrationRepository(String keycloakAuthServerUrl, ClientRegistration baseClientRegistration) {
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.baseClientRegistration = baseClientRegistration;

        // Configurar los tenants conocidos y sus datos correspondientes en Keycloak.
        // Cada entrada asocia un segmento de la URL (el "nombre" del tenant en la URL)
        // con los detalles de su Realm en Keycloak (realmName, clientId, clientSecret).
        tenantMapping.put("plexus", new TenantInfo("plexus-realm", "mi-app-plexus", "APE7Jo7L22EY8yTKh50v6B82nQ8l3f24"));
        tenantMapping.put("inditex", new TenantInfo("inditex-realm", "mi-app-inditex", "5LR8rwO0VLFpog0lCrxrODfxlwQEEj7g"));

        // Se pueden agregar más tenants aquí según sea necesario.
    }

    /**
     * Busca y devuelve la configuración de cliente OAuth2 ({@link ClientRegistration})
     * para el `registrationId` solicitado. Este método es invocado por Spring Security
     * cuando necesita los detalles de un cliente para iniciar o completar un flujo de autenticación.
     * <p>
     * La lógica aquí detecta el tenant a partir de la URI de la solicitud HTTP actual
     * para construir una {@link ClientRegistration} específica para ese tenant.
     *
     * @param registrationId El ID de registro solicitado por Spring Security (ej., "keycloak" o un nombre de tenant).
     * @return La configuración completa del cliente OAuth2 ({@link ClientRegistration}) para el tenant detectado.
     * Si no se encuentra un tenant mapeado, se retorna la configuración base (puede llevar a errores).
     */
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        System.out.println("=======================================");
        System.out.println("===> Buscando registro para: " + registrationId);

        // Obtener el HttpServletRequest actual para analizar la URL.
        // Esto es necesario para extraer el segmento del path que indica el tenant.
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String requestUri = request.getRequestURI();
        System.out.println("=======================================");
        System.out.println("requestUri: " + requestUri);

        // Detectar el segmento del path que corresponde al tenant (ej. "plexus" en "/plexus/home").
        String tenantPathSegment = null;
        for (String pathSegment : tenantMapping.keySet()) {
            if (requestUri.startsWith("/" + pathSegment + "/")) {
                tenantPathSegment = pathSegment;
                break;
            }
        }

        // Si no se pudo detectar el tenant en la URL, se asume que el 'registrationId'
        // es el nombre del tenant. Esto es útil para rutas iniciales o callbacks genéricos.
        if (tenantPathSegment == null) {
            tenantPathSegment = registrationId;
        }

        // Obtener la información del tenant desde el mapeo estático.
        TenantInfo tenantInfo = tenantMapping.get(tenantPathSegment);
        if (tenantInfo == null) {
            // Si no se encuentra información para el tenant, se imprime un error
            // y se devuelve la configuración base, lo cual podría no funcionar correctamente.
            System.err.println("No se encontró tenant para la URI: " + requestUri + ". Usando configuración base (puede fallar).");
            return baseClientRegistration;
        }

        // Extraer los detalles específicos del tenant.
        String realmName = tenantInfo.realm();
        String clientId = tenantInfo.clientId();
        String clientSecret = tenantInfo.clientSecret();

        // Construir una nueva instancia de ClientRegistration basada en la configuración base,
        // pero con los detalles específicos del tenant.
        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(baseClientRegistration)
                .registrationId(registrationId) // Mantener el registrationId original
                .clientId(clientId) // Establecer el Client ID específico del tenant
                .clientSecret(clientSecret) // Establecer el Client Secret específico del tenant
                .scope(baseClientRegistration.getScopes()) // Mantener los scopes base
                // Construir la URI de redirección dinámica, específica para este tenant.
                .redirectUri(buildDynamicRedirectUri(request, tenantPathSegment, registrationId))
                // Actualizar los endpoints de Keycloak con el nombre de realm específico.
                .authorizationUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/" + realmName)
                .userNameAttributeName(IdTokenClaimNames.SUB) // Usar 'sub' como nombre de atributo de usuario por defecto
                .build();

        // Logs de depuración para verificar la configuración del cliente dinámico.
        System.out.println("=======================================");
        System.out.println("===> Realm: " + realmName);
        System.out.println("===> Client ID: " + clientId);
        System.out.println("===> Client Secret: [PROTECTED]"); // No imprimir el secreto en logs de prod.
        System.out.println("===> Redirect URI: " + clientRegistration.getRedirectUri());
        System.out.println("===> Issuer URI: " + clientRegistration.getProviderDetails().getIssuerUri());

        // Guardar la configuración del cliente recién creada en la caché.
        // La clave de la caché es el segmento del path del tenant.
        registrations.put(tenantPathSegment, clientRegistration);
        return clientRegistration;
    }

    /**
     * Construye dinámicamente la URI de redirección (redirect URI) que se enviará a Keycloak
     * al iniciar el flujo de autenticación OAuth2. Esta URI debe ser una de las registradas
     * en Keycloak para el cliente.
     * <p>
     * Se genera basándose en la URL de la solicitud actual para mantener la consistencia
     * con el entorno de ejecución (ej. "http://localhost:8081").
     *
     * @param request            La solicitud HTTP actual.
     * @param tenantPathSegment  El segmento de path del tenant (ej. "plexus").
     * @param registrationId     El ID de registro (generalmente el mismo que el segmento del tenant en este contexto).
     * @return La URI completa de redirección para el login OAuth2 (ej. "http://localhost:8081/login/oauth2/code/keycloak").
     */
    private String buildDynamicRedirectUri(HttpServletRequest request, String tenantPathSegment, String registrationId) {
        // Construye la URI de redirección:
        // 1. Toma la URL completa de la solicitud actual.
        // 2. Reemplaza el path con el path de callback estándar de Spring Security OAuth2.
        //    request.getContextPath() asegura que la URL sea relativa a la raíz del contexto de la aplicación.
        // 3. Elimina cualquier parámetro de consulta existente para asegurar una URI limpia.
        return UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString())
                .replacePath(request.getContextPath() + "/login/oauth2/code/" + registrationId)
                .replaceQuery(null)
                .build()
                .toUriString();
    }
}
