package com.example.keycloak.multitenant;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(KeycloakProperties.class)
public class KeycloakMultitenantApplication {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakMultitenantApplication.class, args);
	}

}
