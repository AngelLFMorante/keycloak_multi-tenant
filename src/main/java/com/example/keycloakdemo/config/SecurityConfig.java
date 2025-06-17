package com.example.keycloakdemo.config;

import com.example.keycloakdemo.repository.DynamicClientRegistrationRepository;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String baseClientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String baseClientSecret; // Aunque puede que no se use para clientes públicos

    @Value("${spring.security.oauth2.client.registration.keycloak.scope}")
    private String[] baseScopes;

    private final String KEYCLOAK_AUTHORITY_PREFIX = "ROLE_";

    private final CustomAuthenticationSuccessHandler successHandler;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        // Build a base ClientRegistration from properties. This serves as a template.
        ClientRegistration base = ClientRegistration.withRegistrationId("keycloak")
                .clientId(baseClientId)
                .clientSecret(baseClientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(baseScopes)
                .authorizationUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/{realmName}")
                .userNameAttributeName("preferred_username")
                .build();

        return new DynamicClientRegistrationRepository(keycloakAuthServerUrl, base);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/public/**", "/error").permitAll()
                        .requestMatchers("/plexus/login", "/inditex/login").permitAll()  // Permitir estas rutas sin login
                        .requestMatchers("/plexus/**", "/inditex/**").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(this.oidcUserService())
                        )
                        .successHandler(successHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );
        return http.build();
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // Extract roles from realm_access.roles (realm roles)
            Map<String, Object> realmAccess = oidcUser.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Collection<String> realmRoles = (Collection<String>) realmAccess.get("roles");
                realmRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
            }

            // Extract roles from resource_access.<client-id>.roles (client roles)
            Map<String, Object> resourceAccess = oidcUser.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                // Get the current client ID dynamically from the user request
                String currentClientId = userRequest.getClientRegistration().getClientId();
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(currentClientId);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    Collection<String> clientRoles = (Collection<String>) clientAccess.get("roles");
                    clientRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
                }
            }

            mappedAuthorities.addAll(oidcUser.getAuthorities());

            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            // This handler is called after Spring Security's internal logout processing.
            // Spring Security's OAuth2 client module usually handles the OIDC RP-initiated logout
            // by redirecting to the IdP's end_session_endpoint if configured correctly.
            // If you need specific redirects after Keycloak finishes its logout,
            // you might need to construct the URL here using Keycloak's logout endpoint
            // and the post_logout_redirect_uri parameter.
            // For now, redirect to the app's root.
            response.sendRedirect("/");
        };
    }
}