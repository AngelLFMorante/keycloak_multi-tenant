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
 * Repositorio personalizado que permite registrar dinámicamente configuraciones de clientes OAuth2
 * en función del tenant (inquilino) detectado a partir de la URL de la solicitud.
 * <p>
 * Útil para aplicaciones multi-tenant donde cada tenant tiene su propio Realm y configuración en Keycloak.
 */
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    // Caché de configuraciones de clientes ya creadas para evitar regenerarlas en cada solicitud
    private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();

    private final String keycloakAuthServerUrl;
    private final ClientRegistration baseClientRegistration;

    /**
     * Mapeo entre el segmento del path del tenant (por ejemplo "inditex") y su configuración en Keycloak.
     * Clave: segmento del path de la URL. Valor: objeto con realm, clientId y clientSecret.
     */
    private final Map<String, TenantInfo> tenantMapping = new HashMap<>();

    /**
     * Constructor principal del repositorio dinámico.
     *
     * @param keycloakAuthServerUrl     URL base del servidor de autenticación de Keycloak
     * @param baseClientRegistration    Configuración base desde la cual se derivan las dinámicas
     */
    public DynamicClientRegistrationRepository(String keycloakAuthServerUrl, ClientRegistration baseClientRegistration) {
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.baseClientRegistration = baseClientRegistration;

        // Configurar los tenants conocidos y sus datos correspondientes en Keycloak
        tenantMapping.put("plexus", new TenantInfo("plexus-realm", "mi-app-plexus", "APE7Jo7L22EY8yTKh50v6B82nQ8l3f24"));
        tenantMapping.put("inditex", new TenantInfo("inditex-realm", "mi-app-inditex", "5LR8rwO0VLFpog0lCrxrODfxlwQEEj7g"));

        // Puedes agregar más tenants aquí según sea necesario
    }

    /**
     * Devuelve la configuración del cliente OAuth2 asociada con el `registrationId` solicitado.
     * Spring Security invoca este método automáticamente durante el flujo de autenticación.
     *
     * @param registrationId El ID de registro solicitado (e.g., "inditex", "plexus")
     * @return La configuración completa del cliente OAuth2 (ClientRegistration)
     */
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        System.out.println("=======================================");
        System.out.println("===> Buscando registro para: " + registrationId);

        // Obtener el HttpServletRequest actual
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String requestUri = request.getRequestURI();
        System.out.println("=======================================");
        System.out.println("requestUri: " + requestUri);

        // Detectar tenant a partir del path de la URL, por ejemplo "/inditex/home"
        String tenantPathSegment = null;
        for (String pathSegment : tenantMapping.keySet()) {
            if (requestUri.startsWith("/" + pathSegment + "/")) {
                tenantPathSegment = pathSegment;
                break;
            }
        }

        // Si no se encuentra en la URL, usar el registrationId como nombre del tenant
        if (tenantPathSegment == null) {
            tenantPathSegment = registrationId;
        }

        TenantInfo tenantInfo = tenantMapping.get(tenantPathSegment);
        if (tenantInfo == null) {
            System.err.println("No se encontró tenant para la URI: " + requestUri + ". Usando configuración base (puede fallar).");
            return baseClientRegistration;
        }

        // Extraer información del tenant
        String realmName = tenantInfo.realm();
        String clientId = tenantInfo.clientId();
        String clientSecret = tenantInfo.clientSecret();

        // Crear ClientRegistration específico para el tenant
        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(baseClientRegistration)
                .registrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret) // Requerido si el cliente en Keycloak no es público
                .scope(baseClientRegistration.getScopes())
                .redirectUri(buildDynamicRedirectUri(request, tenantPathSegment, registrationId))
                .authorizationUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/" + realmName)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();

        // Logs de depuración para verificación
        System.out.println("=======================================");
        System.out.println("===> Realm: " + realmName);
        System.out.println("===> Client ID: " + clientId);
        System.out.println("===> Client Secret: " + clientSecret);
        System.out.println("===> Redirect URI: " + clientRegistration.getRedirectUri());
        System.out.println("===> Issuer URI: " + clientRegistration.getProviderDetails().getIssuerUri());

        // Guardar en caché para evitar recrearlo en futuras peticiones
        registrations.put(tenantPathSegment, clientRegistration);
        return clientRegistration;
    }

    /**
     * Construye dinámicamente la URI de redirección (redirect URI) que se enviará a Keycloak
     * al iniciar el flujo de autenticación.
     *
     * @param request            La solicitud HTTP actual
     * @param tenantPathSegment  Segmento de path del tenant (por ejemplo: "inditex")
     * @param registrationId     ID de registro (mismo que tenant en este caso)
     * @return La URI completa de redirección para el login OAuth2
     */
    private String buildDynamicRedirectUri(HttpServletRequest request, String tenantPathSegment, String registrationId) {
        return UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString())
                .replacePath(request.getContextPath() + "/login/oauth2/code/" + registrationId)
                .replaceQuery(null) // Elimina cualquier parámetro de consulta existente
                .build()
                .toUriString();
    }
}
