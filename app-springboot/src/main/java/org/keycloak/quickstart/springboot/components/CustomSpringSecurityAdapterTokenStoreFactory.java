package org.keycloak.quickstart.springboot.components;

import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.springsecurity.token.AdapterTokenStoreFactory;
import org.keycloak.adapters.springsecurity.token.SpringSecurityTokenStore;
import org.keycloak.enums.TokenStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomSpringSecurityAdapterTokenStoreFactory implements AdapterTokenStoreFactory {

    public AdapterTokenStore createAdapterTokenStore(KeycloakDeployment deployment, HttpServletRequest request, HttpServletResponse response) {
        AdapterTokenStore adapterTokenStore = null;
        if (deployment.getTokenStore() == TokenStore.COOKIE) {
            adapterTokenStore = new CustomSpringSecurityCookieTokenStore(deployment, request, response);
        } else if (deployment.getTokenStore() == TokenStore.SESSION) {
            adapterTokenStore = new SpringSecurityTokenStore(deployment, request);
        }

        return adapterTokenStore;
    }

    public AdapterTokenStore createAdapterTokenStore(KeycloakDeployment deployment, HttpServletRequest request) {
        return null;
    }
}
