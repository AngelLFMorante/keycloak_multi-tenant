package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UserAccountService {

    private static final Logger log = LoggerFactory.getLogger(UserAccountService.class);
    private final KeycloakAdminService adminService;

    public UserAccountService(KeycloakAdminService adminService) {
        this.adminService = adminService;
    }

    public void markEmailVerified(String realm, String userId) {
        RealmResource realmResource = adminService.getRealmResource(realm);
        var user = realmResource.users().get(userId).toRepresentation();
        user.setEmailVerified(true);
        realmResource.users().get(userId).update(user);
        log.info("Email verificado para usuario {}", userId);
    }

    public void enableUser(String realm, String userId) {
        RealmResource realmResource = adminService.getRealmResource(realm);
        var user = realmResource.users().get(userId).toRepresentation();
        user.setEnabled(true);
        realmResource.users().get(userId).update(user);
        log.info("Usuario {} habilitado", userId);
    }

    public void resetUserPassword(String realm, String userId, String newPassword) {
        RealmResource realmResource = adminService.getRealmResource(realm);
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(newPassword);
        cred.setTemporary(false);
        realmResource.users().get(userId).resetPassword(cred);
        log.info("Contraseña restablecida para {}", userId);
    }
}
