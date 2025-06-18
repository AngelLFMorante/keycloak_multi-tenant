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

public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();
    private final String keycloakAuthServerUrl;
    private final ClientRegistration baseClientRegistration;

    // Map the tenant path segment to its corresponding Keycloak realm name and client ID
    private final Map<String, TenantInfo> tenantMapping = new HashMap<>(); // Key: path segment (e.g., "plexus"), Value: [Keycloak Realm Name, Keycloak Client ID]

    public DynamicClientRegistrationRepository(String keycloakAuthServerUrl, ClientRegistration baseClientRegistration) {
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.baseClientRegistration = baseClientRegistration;

        // Configure your tenants here
        // Key: tenant (path segment), Value: [realmName, clientId, clientSecret]
        tenantMapping.put("plexus", new TenantInfo("plexus-realm", "mi-app-plexus", "APE7Jo7L22EY8yTKh50v6B82nQ8l3f24"));
        tenantMapping.put("inditex", new TenantInfo("inditex-realm", "mi-app-inditex", "5LR8rwO0VLFpog0lCrxrODfxlwQEEj7g"));

        // Add more tenants
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        // This method is called by Spring Security to get the ClientRegistration.
        // The 'registrationId' here is usually "keycloak" as configured in application.properties template.
        // We need to dynamically determine the actual realm based on the current request.
        System.out.println("=======================================");
        System.out.println("===> Buscando registro para: " + registrationId);

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String requestUri = request.getRequestURI();
        System.out.println("=======================================");
        System.out.println("requestUri: " + request.getRequestURI());

        // Extract tenant from URL path (e.g., /plexus/home -> plexus)
        String tenantPathSegment = null;
        for (String pathSegment : tenantMapping.keySet()) {
            if (requestUri.startsWith("/" + pathSegment + "/")) {
                tenantPathSegment = pathSegment;
                break;
            }
        }

        // Si no se detecta el tenant por la URI, usar el registrationId que viene como parámetro
        if (tenantPathSegment == null) {
            tenantPathSegment = registrationId;
        }

        TenantInfo tenantInfo = tenantMapping.get(tenantPathSegment);
        if (tenantInfo  == null) {
            // Fallback for root path or other non-tenant specific paths, or error
            // You might want to handle this differently, e.g., throw an exception
            // or redirect to a default tenant selection page.
            System.err.println("No tenant path segment found for URI: " + requestUri + ". Returning base/default client.");
            // If you have a default realm/client, you could return it here.
            // For now, we return the base client, which will likely fail due to wrong issuer/redirect URI.
            return baseClientRegistration;
        }

        String realmName = tenantInfo.realm();
        String clientId = tenantInfo.clientId();
        String clientSecret = tenantInfo.clientSecret();

        // Construct the dynamic ClientRegistration for the specific tenant
        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(baseClientRegistration)
                .registrationId(registrationId) // Use "plexus", "inditex", etc. como registrationId
                .clientId(clientId) // Set the actual client ID for the tenant
                // Client Secret is only needed if Keycloak client is "confidential" and not "public"
                // For a multi-tenant app with frontend redirect, clients are usually "public",
                // so you might not need to set clientSecret dynamically unless it varies.
                .clientSecret(clientSecret) // If client secret varies per tenant/client ID
                .scope(baseClientRegistration.getScopes()) // Keep original scopes or customize
                .redirectUri(buildDynamicRedirectUri(request, tenantPathSegment, registrationId))
                .authorizationUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/" + realmName + "/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/" + realmName) // Set the dynamic issuer URI
                .userNameAttributeName(IdTokenClaimNames.SUB) // Or 'preferred_username' if you prefer
                .build();
        System.out.println("=======================================");
        System.out.println("===> Realm: " + realmName);
        System.out.println("===> Client ID: " + clientId);
        System.out.println("===> Client Secret: " + clientSecret);
        System.out.println("===> Redirect URI: " + clientRegistration.getRedirectUri());
        System.out.println("===> Issuer URI: " + clientRegistration.getProviderDetails().getIssuerUri());

        // Cache the dynamically created client registration for subsequent requests
        registrations.put(tenantPathSegment, clientRegistration); // Cache by tenant path segment
        return clientRegistration;
    }

    private String buildDynamicRedirectUri(HttpServletRequest request, String tenantPathSegment, String registrationId) {
        // Construct the redirect URI based on the current request context and tenant.
        return UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString())
                .replacePath(request.getContextPath() + "/login/oauth2/code/" + registrationId)
                .replaceQuery(null) // Remove any existing query parameters
                .build()
                .toUriString();
    }
}
