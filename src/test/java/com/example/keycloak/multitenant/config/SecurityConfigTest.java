package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.security.KeycloakAuthenticationProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest(
        properties = {
                "spring.main.allow-bean-definition-overriding=true",
                "keycloak.auth-server-url=http://localhost:8080/auth",
                "keycloak.realm-mapping.test-realm=test-keycloak-realm"
        }
)
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext applicationContext;

    @InjectMocks
    private SecurityConfig securityConfig;

    @Mock
    private KeycloakAuthenticationProvider mockKeycloakAuthenticationProvider;


    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(applicationContext)
                .apply(springSecurity())
                .build();
    }

    @Test
    @DisplayName("Debería permitir acceso POST a /realm/register sin autenticación")
    void securityFilterChain_shouldPermitPostRegister() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/any-realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("CSRF debería estar deshabilitado")
    void securityFilterChain_csrfShouldBeDisabled() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/any-realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest()); // Sigue siendo 400 del controlador, no 403 CSRF.
    }

    @Test
    @DisplayName("El endpoint de logout debería funcionar y limpiar la autenticación")
    @WithMockUser("testuser")
    void securityFilterChain_logoutShouldWork() throws Exception {
        mockMvc.perform(logout("/logout"))
                .andExpect(status().isOk())
                .andExpect(unauthenticated());
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

    @Test
    @DisplayName("customLogoutSuccessHandler debería ser un LogoutSuccessHandler y establecer el estado OK")
    void customLogoutSuccessHandler_shouldSetStatusOk() throws Exception {
        LogoutSuccessHandler handler = securityConfig.customLogoutSuccessHandler();
        assertNotNull(handler);

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        Authentication mockAuthentication = mock(Authentication.class);

        when(mockAuthentication.getName()).thenReturn("testUser");

        handler.onLogoutSuccess(mockRequest, mockResponse, mockAuthentication);

        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
        verify(mockAuthentication, times(1)).getName();
    }
}