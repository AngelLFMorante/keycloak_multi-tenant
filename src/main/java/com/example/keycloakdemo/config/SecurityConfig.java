package com.example.keycloakdemo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/webjars/**",
                                "/register",
                                "/error",
                                "/pending"
                        ).permitAll()

                        // *** AHORA PERMITIMOS EL POST A LA NUEVA RUTA DE PROCESAMIENTO ***
                        .requestMatchers(HttpMethod.POST, "/do_login").permitAll() // <--- ¡NUEVA RUTA!

                        .requestMatchers(HttpMethod.POST, "/plexus/process_register").permitAll()

                        .anyRequest().authenticated()
                )
                // Aquí es donde ajustamos formLogin().
                // No queremos que Spring Security procese el POST del formulario por defecto,
                // ya que lo haremos nosotros mismos en /do_login.
                // Sin embargo, necesitamos el .loginPage("/login") para que Spring Security sepa
                // dónde redirigir a los usuarios no autenticados y para la funcionalidad de logout.
                .formLogin(form -> form
                                .loginPage("/login")        // La URL para mostrar el formulario (GET)
                                .permitAll() // Permitimos el acceso a la página de login (GET)
                        // IMPORTANTE: NO uses .loginProcessingUrl() si quieres que tu @PostMapping lo maneje
                        // La ausencia de .loginProcessingUrl() con permitAll() en POST /do_login
                        // y el formulario apuntando a /do_login es clave.
                        // La defaultSuccessUrl y failureUrl pueden ser manejadas por tu controlador en /do_login
                        // mediante redirecciones explícitas.
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                // Si no utilizas el flujo de OAuth2/OIDC para el login de usuarios finales,
                // podrías considerar eliminar la sección .oauth2Login().
                // Si la mantienes, asegúrate de que no cause conflictos.
                .oauth2Login(oauth2 -> oauth2
                                .loginPage("/login") // OJO: Si esto redirige a Keycloak, puede ser otra forma de login.
                        // Asegúrate de que no se superpongan las intenciones.
                )
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}