package com.example.keycloakdemo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Carga la configuración de tenants desde application.yml
 */
@Component
@ConfigurationProperties(prefix = "tenants")
public class TenantProperties {

    private Map<String, TenantConfig> tenants = new HashMap<>();

    public Map<String, TenantConfig> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, TenantConfig> tenants) {
        this.tenants = tenants;
    }

    public boolean isValidTenant(String tenantKey) {
        return tenants.containsKey(tenantKey);
    }

    public TenantConfig getTenantInfo(String tenantKey) {
        return tenants.get(tenantKey);
    }

    public static class TenantConfig {
        private String realm;
        private String clientId;
        private String clientSecret;

        public String getRealm() {
            return realm;
        }

        public void setRealm(String realm) {
            this.realm = realm;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }
    }
}
