package org.keycloak.quickstart.springboot.components;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomKeycloakLogoutHandler extends KeycloakLogoutHandler {

    private final Logger log = LoggerFactory.getLogger(CustomKeycloakLogoutHandler.class);
    private AdapterDeploymentContext adapterDeploymentContext;
    private CustomSpringSecurityAdapterTokenStoreFactory adapterTokenStoreFactory = new CustomSpringSecurityAdapterTokenStoreFactory();

    public CustomKeycloakLogoutHandler(AdapterDeploymentContext adapterDeploymentContext) {
        super(adapterDeploymentContext);
        this.adapterDeploymentContext = adapterDeploymentContext;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            super.logout(request, response, authentication);
        } catch (Exception e) {
            log.error("logout operation failed " + e.getMessage(), e);
        }

        try {
            HttpFacade facade = new SimpleHttpFacade(request, response);
            KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(facade);
            adapterTokenStoreFactory.createAdapterTokenStore(deployment, request, response).logout();
        } catch (Exception e) {
            log.error("logout operation failed " + e.getMessage(), e);
        }

        try {
            request.logout();
        } catch (ServletException e) {
            log.error("logout operation failed " + e.getMessage(), e);
        }
    }
}
