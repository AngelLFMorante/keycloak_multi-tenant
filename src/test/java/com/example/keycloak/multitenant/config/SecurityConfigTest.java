package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.security.KeycloakAuthenticationProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext applicationContext;

    private SecurityConfig securityConfig;

    @Autowired(required = false)
    private ObjectMapper objectMapper;

    @Mock
    private KeycloakAuthenticationProvider mockKeycloakAuthenticationProvider;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private HttpSession mockSession;

    private KeycloakProperties keycloakProperties;


    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(applicationContext)
                .apply(springSecurity())
                .build();

        keycloakProperties = new KeycloakProperties();
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put("test-realm", "realm-test-id");

        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put("test-client", "secret123");

        keycloakProperties.setRealmMapping(realmMapping);
        keycloakProperties.setClientSecrets(clientSecrets);

        securityConfig = new SecurityConfig();
    }

    @Test
    @DisplayName("Debería permitir acceso POST a /api/v1/{realm}/register sin autenticación")
    void securityFilterChain_shouldPermitPostRegister() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/api/v1/realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("CSRF debería estar deshabilitado")
    void securityFilterChain_csrfShouldBeDisabled() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/api/v1/realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest()); // Sigue siendo 400 del controlador, no 403 CSRF.
    }


    @Test
    @DisplayName("authenticationManager debería ser un ProviderManager y contener KeycloakAuthenticationProvider")
    void authenticationManager_shouldBeProviderManagerWithKeycloakProvider() {
        AuthenticationManager manager = securityConfig.authenticationManager(mockKeycloakAuthenticationProvider);

        assertNotNull(manager);
        assertTrue(manager instanceof ProviderManager);
        ProviderManager providerManager = (ProviderManager) manager;
        assertTrue(providerManager.getProviders().contains(mockKeycloakAuthenticationProvider));
        assertEquals(1, providerManager.getProviders().size());
    }

    @Test
    @DisplayName("userDetailsService debería devolver un UserDetails con la contraseña dummy")
    void userDetailsService_shouldReturnUserDetailsWithDummyPassword() {
        UserDetailsService service = securityConfig.userDetailsService();
        assertNotNull(service);

        String username = "testuser";
        UserDetails userDetails = service.loadUserByUsername(username);

        assertNotNull(userDetails);
        assertEquals(username, userDetails.getUsername());
        assertEquals(SecurityConfig.DUMMY_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
    }

    @Test
    @DisplayName("securityContextRepository debería ser HttpSessionSecurityContextRepository")
    void securityContextRepository_shouldBeHttpSessionSecurityContextRepository() {
        SecurityContextRepository repository = securityConfig.securityContextRepository();
        assertNotNull(repository);
        assertTrue(repository instanceof HttpSessionSecurityContextRepository);
    }

    @Test
    @DisplayName("restTemplate debería devolver una instancia de RestTemplate")
    void restTemplate_shouldReturnRestTemplateInstance() {
        RestTemplate restTemplate = securityConfig.restTemplate();
        assertNotNull(restTemplate);
        assertTrue(restTemplate instanceof RestTemplate);
    }
}