package com.example.keycloakdemo.repository;

import com.example.keycloakdemo.config.TenantProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Repositorio dinámico de registros de cliente OAuth2.
 * <p>
 * Este componente detecta el tenant desde la URI de la petición entrante
 * y construye dinámicamente una instancia {@link ClientRegistration}
 * utilizando la configuración específica del tenant (realm, clientId y secret).
 *
 * <p>
 * Utiliza como plantilla un {@code baseClientRegistration} predefinido
 * y sustituye dinámicamente valores como issuer, URIs y credenciales.
 */
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();
    private final String keycloakAuthServerUrl;
    private final ClientRegistration baseClientRegistration;
    private final TenantProperties tenantProperties;

    /**
     * Constructor principal.
     *
     * @param keycloakAuthServerUrl     URL base del servidor de autenticación Keycloak (ej. http://localhost:8080)
     * @param baseClientRegistration    Registro de cliente base usado como plantilla
     * @param tenantProperties          Configuración de tenants, cargada desde application.yml
     */
    public DynamicClientRegistrationRepository(String keycloakAuthServerUrl,
                                               ClientRegistration baseClientRegistration,
                                               TenantProperties tenantProperties) {
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.baseClientRegistration = baseClientRegistration;
        this.tenantProperties = tenantProperties;
    }

    /**
     * Busca un {@link ClientRegistration} por su ID (usualmente el nombre del tenant).
     * <p>
     * Detecta el tenant desde la URI entrante y construye dinámicamente
     * una instancia de {@code ClientRegistration} usando los datos
     * definidos en application.yml.
     *
     * @param registrationId ID de registro (se usa como fallback si no se detecta tenant en la URI)
     * @return Registro de cliente para el tenant correspondiente
     */
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String requestUri = request.getRequestURI();
        System.out.println("requestUri: " + requestUri);

        // Detectar tenant desde el path de la URI
        String tenantKey = tenantProperties.getTenants().keySet().stream()
                .filter(segment -> requestUri.startsWith("/" + segment + "/"))
                .findFirst()
                .orElse(registrationId);

        TenantProperties.TenantConfig tenantConfig = tenantProperties.getTenantInfo(tenantKey);
        if (tenantConfig == null) {
            System.err.println("Tenant no encontrado para URI: " + requestUri);
            return baseClientRegistration;
        }

        // Si ya está en caché, devolverlo
        if (registrations.containsKey(tenantKey)) {
            return registrations.get(tenantKey);
        }

        String realmName = tenantConfig.getRealm();
        String clientId = tenantConfig.getClientId();
        String clientSecret = tenantConfig.getClientSecret();

        // Construcción dinámica del ClientRegistration
        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(baseClientRegistration)
                .registrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .scope(baseClientRegistration.getScopes())
                .redirectUri(buildDynamicRedirectUri(request, tenantKey))
                .authorizationUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/" + realmName)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName(clientId)
                .build();

        // Cachearlo para mejorar rendimiento
        registrations.put(tenantKey, clientRegistration);
        return clientRegistration;
    }

    /**
     * Construye dinámicamente el URI de redirección basado en la URL de la solicitud y el tenant.
     *
     * @param request   La solicitud HTTP actual
     * @param tenantKey El identificador del tenant
     * @return URI de redirección personalizado
     */
    private String buildDynamicRedirectUri(HttpServletRequest request, String tenantKey) {
        return UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString())
                .replacePath(request.getContextPath() + "/" + tenantKey + "/login/oauth2/code/" + tenantKey)
                .replaceQuery(null)
                .build()
                .toUriString();
    }
}
