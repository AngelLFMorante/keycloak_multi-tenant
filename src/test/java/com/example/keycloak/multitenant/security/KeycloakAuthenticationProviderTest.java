package com.example.keycloak.multitenant.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link KeycloakAuthenticationProvider}.
 * Verifica que el proveedor de autenticación se comporte correctamente,
 * cargando UserDetails y construyendo el token de autenticación final.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationProviderTest {

    @InjectMocks
    private KeycloakAuthenticationProvider keycloakAuthenticationProvider;

    @Mock
    private UserDetailsService userDetailsService;

    private String testUsername = "testuser";
    private String testPassword = "dummyPassword";
    private List<GrantedAuthority> testAuthorities;
    private UserDetails testUserDetails;

    @BeforeEach
    void setUp() {
        testAuthorities = Arrays.asList(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("SCOPE_read"),
                new SimpleGrantedAuthority("SCOPE_write")
        );

        testUserDetails = new User(testUsername, "N/A", testAuthorities);
    }

    @Test
    @DisplayName("Debería lanzar AuthenticationException si UserDetailsService falla")
    void authenticate_shouldThrowAuthenticationExceptionIfUserDetailsServiceFails() {
        when(userDetailsService.loadUserByUsername(testUsername)).thenThrow(new AuthenticationException("Usuario no encontrado") {});

        Authentication preAuthenticatedToken = new UsernamePasswordAuthenticationToken(
                testUsername,
                testPassword,
                testAuthorities
        );

        assertThrows(AuthenticationException.class, () -> {
            keycloakAuthenticationProvider.authenticate(preAuthenticatedToken);
        }, "Debería lanzar AuthenticationException si UserDetailsService falla.");

        verify(userDetailsService, times(1)).loadUserByUsername(testUsername);
    }

    @Test
    @DisplayName("supports() debería retornar true para UsernamePasswordAuthenticationToken")
    void supports_shouldReturnTrueForUsernamePasswordAuthenticationToken() {
        assertTrue(keycloakAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class),
                "supports() debería retornar true para UsernamePasswordAuthenticationToken.");
    }

    @Test
    @DisplayName("supports() debería retornar false para clases de autenticación no compatibles")
    void supports_shouldReturnFalseForUnsupportedAuthenticationClasses() {
        assertFalse(keycloakAuthenticationProvider.supports(org.springframework.security.authentication.BadCredentialsException.class),
                "supports() debería retornar false para BadCredentialsException.");
        assertFalse(keycloakAuthenticationProvider.supports(org.springframework.security.authentication.AnonymousAuthenticationToken.class),
                "supports() debería retornar false para AnonymousAuthenticationToken.");
    }
}