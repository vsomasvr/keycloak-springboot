package org.keycloak.quickstart.springboot.components;

import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.adapters.springsecurity.authentication.RequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.QueryParamPresenceRequestMatcher;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomKeycloakAuthenticationProcessingFilter extends KeycloakAuthenticationProcessingFilter {

    public static final RequestMatcher DEFAULT_REQUEST_MATCHER =
        new OrRequestMatcher(
            new AntPathRequestMatcher(DEFAULT_LOGIN_URL),
            new RequestHeaderRequestMatcher(AUTHORIZATION_HEADER),
            new QueryParamPresenceRequestMatcher(OAuth2Constants.ACCESS_TOKEN),
            new CookieRequestMatcher()
        );

    private ApplicationContext applicationContext;
    private AdapterDeploymentContext adapterDeploymentContext;
    private AuthenticationManager authenticationManager;
    private RequestAuthenticatorFactory requestAuthenticatorFactory = new SpringSecurityRequestAuthenticatorFactory();


    private CustomSpringSecurityAdapterTokenStoreFactory adapterTokenStoreFactory = new CustomSpringSecurityAdapterTokenStoreFactory();


    public CustomKeycloakAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager, DEFAULT_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
    }

    public CustomKeycloakAuthenticationProcessingFilter(AuthenticationManager authenticationManager, RequestMatcher requiresAuthenticationRequestMatcher) {
        super(authenticationManager, requiresAuthenticationRequestMatcher);
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

//        log.debug("Attempting Keycloak authentication");

        HttpFacade facade = new SimpleHttpFacade(request, response);
        KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(facade);

        // using Spring authenticationFailureHandler
        deployment.setDelegateBearerErrorResponseSending(true);

        AdapterTokenStore tokenStore = adapterTokenStoreFactory.createAdapterTokenStore(deployment, request, response);
        RequestAuthenticator authenticator
                = requestAuthenticatorFactory.createRequestAuthenticator(facade, request, deployment, tokenStore, -1);

        AuthOutcome result = authenticator.authenticate();
//        log.debug("Auth outcome: {}", result);

        if (AuthOutcome.FAILED.equals(result)) {
            AuthChallenge challenge = authenticator.getChallenge();
            if (challenge != null) {
                challenge.challenge(facade);
            }
            throw new KeycloakAuthenticationException("Invalid authorization header, see WWW-Authenticate header for details");
        }

        if (AuthOutcome.NOT_ATTEMPTED.equals(result)) {
            AuthChallenge challenge = authenticator.getChallenge();
            if (challenge != null) {
                challenge.challenge(facade);
            }
            if (deployment.isBearerOnly()) {
                // no redirection in this mode, throwing exception for the spring handler
                throw new KeycloakAuthenticationException("Authorization header not found,  see WWW-Authenticate header");
            } else {
                // let continue if challenged, it may redirect
                return null;
            }
        }

        else if (AuthOutcome.AUTHENTICATED.equals(result)) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Assert.notNull(authentication, "Authentication SecurityContextHolder was null");
            return authenticationManager.authenticate(authentication);
        }
        else {
            AuthChallenge challenge = authenticator.getChallenge();
            if (challenge != null) {
                challenge.challenge(facade);
            }
            return null;
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
        super.setApplicationContext(applicationContext);
    }

    @Override
    public void afterPropertiesSet() {
        adapterDeploymentContext = applicationContext.getBean(AdapterDeploymentContext.class);
        super.afterPropertiesSet();
    }

    /**
     * Sets the request authenticator factory to use when creating per-request authenticators.
     *
     * @param requestAuthenticatorFactory the <code>RequestAuthenticatorFactory</code> to use
     */
    public void setRequestAuthenticatorFactory(RequestAuthenticatorFactory requestAuthenticatorFactory) {
        Assert.notNull(requestAuthenticatorFactory, "RequestAuthenticatorFactory cannot be null");
        this.requestAuthenticatorFactory = requestAuthenticatorFactory;
        super.setRequestAuthenticatorFactory(requestAuthenticatorFactory);
    }
}
