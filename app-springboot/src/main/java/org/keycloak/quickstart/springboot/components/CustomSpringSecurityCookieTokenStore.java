package org.keycloak.quickstart.springboot.components;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.*;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.adapters.springsecurity.token.SpringSecurityTokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter.DEFAULT_LOGIN_URL;

public class CustomSpringSecurityCookieTokenStore extends SpringSecurityTokenStore {

    private final Logger logger = LoggerFactory.getLogger(CustomSpringSecurityCookieTokenStore.class);

    public static final RequestMatcher interactiveRequestMatcher =
        new OrRequestMatcher(
            new AntPathRequestMatcher(DEFAULT_LOGIN_URL)
        );

    private final KeycloakDeployment deployment;
    private final HttpFacade facade;
    private final HttpServletRequest request;

    public CustomSpringSecurityCookieTokenStore(KeycloakDeployment deployment, HttpServletRequest request, HttpServletResponse response) {
        super(deployment, request);
        this.deployment = deployment;
        this.facade = new SimpleHttpFacade(request, response);
        this.request = request;
    }

    @Override
    public void checkCurrentToken() {
        if(isAuthenticated()){
            return;
        }
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = getPrincipalFromCookie();
        if (principal != null) {
            RefreshableKeycloakSecurityContext keycloakSecurityContext = principal.getKeycloakSecurityContext();
            OidcKeycloakAccount account = new SimpleKeycloakAccount(principal,
                AdapterUtils.getRolesFromSecurityContext(keycloakSecurityContext), keycloakSecurityContext);
            saveAccountInfo(account);
        }
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        checkCurrentToken();
        return super.isCached(authenticator);
    }

    @Override
    public void refreshCallback(RefreshableKeycloakSecurityContext securityContext) {
        CookieTokenStore.setTokenCookie(deployment, facade, securityContext);
    }

    @Override
    public void saveAccountInfo(OidcKeycloakAccount account) {
        CookieTokenStore.setTokenCookie(deployment, facade,
            (RefreshableKeycloakSecurityContext) account.getKeycloakSecurityContext());

        logger.debug("Saving account info {}", account);
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if(authentication !=null){
//            logger.info("#########################" + "auth exists already");
//        }
        SecurityContextHolder.getContext()
            .setAuthentication(new KeycloakAuthenticationToken(account, isInteractiveRequest(request)));
    }

    @Override
    public void logout() {
        CookieTokenStore.removeCookie(deployment, facade);
        super.logout();
    }

    public KeycloakPrincipal<RefreshableKeycloakSecurityContext> getPrincipalFromCookie() {
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = CookieTokenStore.getPrincipalFromCookie(deployment, facade, this);

        if (principal != null) {
            RefreshableKeycloakSecurityContext keycloakSecurityContext = principal.getKeycloakSecurityContext();
            boolean validOrRefreshed;
            if (deployment.isAlwaysRefreshToken()) {
                validOrRefreshed = keycloakSecurityContext.refreshExpiredToken(false);
            } else {
                validOrRefreshed = keycloakSecurityContext.refreshExpiredToken(true);
            }

            if (!validOrRefreshed) {
                CookieTokenStore.removeCookie(deployment, facade);
                principal = null;
            }
        }

        return principal;
    }

    protected boolean isInteractiveRequest(HttpServletRequest request) {
        return interactiveRequestMatcher.matches(request);
    }

    private boolean isAuthenticated(){
        SecurityContext context = SecurityContextHolder.getContext();
        return context !=null && context.getAuthentication()!=null;
    }
}
