package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.model.LoginResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controlador web para la página de inicio.
 * <p>
 * Este controlador maneja la solicitud de la ruta raíz y determina si el usuario ha iniciado sesión
 * para renderizar la vista de manera apropiada.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Controller
@Tag(name = "Index Web", description = "Endpoint web para la página de inicio.")
public class WebIndexController {

    private static final Logger log = LoggerFactory.getLogger(WebIndexController.class);

    /**
     * Muestra la página de inicio de la aplicación.
     * <p>
     * Este método verifica si hay una sesión de usuario activa y ajusta el modelo
     * de la vista para mostrar los datos de login o los valores por defecto.
     *
     * @param session La sesión HTTP, utilizada para verificar si el usuario ha iniciado sesión.
     * @param model   El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista ("index") a renderizar.
     */
    @Operation(
            summary = "Muestra la página de inicio de la aplicación.",
            description = "Verifica el estado de la sesión y renderiza la vista de inicio con los datos de login si están presentes."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Página de inicio renderizada exitosamente.")
    })
    @GetMapping("/")
    public String index(HttpSession session, Model model) {
        log.info("Accediendo a la página de inicio.");
        LoginResponse loginResponse = (LoginResponse) session.getAttribute("loginResponse");
        boolean isLoggedIn = loginResponse != null;
        model.addAttribute("isLoggedIn", isLoggedIn);

        if (isLoggedIn) {
            log.debug("Sesión de usuario encontrada. Pasando datos de login a la vista.");
            model.addAttribute("tenantId", loginResponse.getRealm());
            model.addAttribute("clientId", loginResponse.getClient());
        } else {
            log.debug("No se encontró sesión de usuario. Usando valores por defecto.");
            model.addAttribute("tenantId", "realm");
            model.addAttribute("clientId", "my-client");
        }

        return "index";
    }
}
