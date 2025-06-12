package com.example.keycloakdemo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpMethod; // ¡IMPORTANTE! Importar HttpMethod para especificar POST

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // Rutas permitidas para todos
                        .requestMatchers(
                                "/**",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/webjars/**",
                                "/register", // GET para mostrar el formulario
                                "/login",
                                "/error",
                                "/pending" // GET para la página de pendiente (con o sin parámetros)
                        ).permitAll() // Permite el acceso a estas rutas GET/POST sin autenticación

                        // Permite específicamente endpoint
                        .requestMatchers(HttpMethod.POST, "/plexus/process_register").permitAll()

                        .anyRequest().authenticated() // Cualquier otra solicitud requiere autenticación
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                )
                // Deshabilita CSRF (Cross-Site Request Forgery).
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}