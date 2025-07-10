package com.example.keycloakdemo.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.util.ReflectionTestUtils; // Para inyectar @Value en tests unitarios

import static org.junit.jupiter.api.Assertions.*;

/**
 * Clase de test unitario para {@link SecurityConfig}.
 * Se enfoca en verificar la correcta creación y configuración de los beans de seguridad
 * definidos en la clase, aislando las dependencias.
 */
@ExtendWith(MockitoExtension.class) // Habilita la integración de Mockito con JUnit 5
class SecurityConfigTest {

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig();
        // Inyectar manualmente los valores de las propiedades @Value para el test unitario
        ReflectionTestUtils.setField(securityConfig, "keycloakAuthServerUrl", "http://localhost:8080/auth");
        // No es necesario inyectar KEYCLOAK_AUTHORITY_PREFIX ya que es una constante final
    }

    @Test
    @DisplayName("Debería crear un AuthenticationManager correctamente configurado")
    void authenticationManager_BeanCreationAndConfiguration() {
        UserDetailsService userDetailsService = securityConfig.userDetailsService();
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        AuthenticationManager authenticationManager = securityConfig.authenticationManager(userDetailsService, passwordEncoder);

        assertNotNull(authenticationManager, "El AuthenticationManager no debería ser nulo");
        assertInstanceOf(ProviderManager.class, authenticationManager, "El AuthenticationManager debería ser una instancia de ProviderManager");

        ProviderManager providerManager = (ProviderManager) authenticationManager;
        assertEquals(1, providerManager.getProviders().size(), "Debería haber un solo proveedor de autenticación");
        assertInstanceOf(DaoAuthenticationProvider.class, providerManager.getProviders().get(0), "El proveedor debería ser DaoAuthenticationProvider");
    }

    @Test
    @DisplayName("Debería crear un UserDetailsService dummy")
    void userDetailsService_BeanCreation() {
        UserDetailsService userDetailsService = securityConfig.userDetailsService();

        assertNotNull(userDetailsService, "El UserDetailsService no debería ser nulo");

        // Verificar que devuelve un UserDetails con la DUMMY_PASSWORD
        UserDetails userDetails = userDetailsService.loadUserByUsername("anyUser");
        assertNotNull(userDetails, "UserDetails no debería ser nulo");
        assertEquals(SecurityConfig.DUMMY_PASSWORD, userDetails.getPassword(), "La contraseña debería ser la dummy");
        assertTrue(userDetails.getAuthorities().isEmpty(), "Las autoridades deberían estar vacías");
        assertEquals("anyUser", userDetails.getUsername(), "El nombre de usuario debería coincidir");
    }

    @Test
    @DisplayName("Debería crear un BCryptPasswordEncoder")
    void passwordEncoder_BeanCreation() {
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        assertNotNull(passwordEncoder, "El PasswordEncoder no debería ser nulo");
        assertInstanceOf(BCryptPasswordEncoder.class, passwordEncoder, "El PasswordEncoder debería ser una instancia de BCryptPasswordEncoder");
    }

    @Test
    @DisplayName("Debería crear un SecurityContextRepository de tipo HttpSessionSecurityContextRepository")
    void securityContextRepository_BeanCreation() {
        SecurityContextRepository securityContextRepository = securityConfig.securityContextRepository();

        assertNotNull(securityContextRepository, "El SecurityContextRepository no debería ser nulo");
        assertInstanceOf(HttpSessionSecurityContextRepository.class, securityContextRepository, "El SecurityContextRepository debería ser HttpSessionSecurityContextRepository");
    }

    @Test
    @DisplayName("Debería crear un LogoutSuccessHandler personalizado")
    void customLogoutSuccessHandler_BeanCreation() {
        // No hay dependencias inyectadas en customLogoutSuccessHandler, así que no necesitamos mocks aquí.
        // Solo verificamos que el bean se crea y no es nulo.
        assertNotNull(securityConfig.customLogoutSuccessHandler(), "El CustomLogoutSuccessHandler no debería ser nulo");
    }
}
