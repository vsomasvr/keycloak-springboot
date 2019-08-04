/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.quickstart.springboot.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.keycloak.quickstart.springboot.components.CustomKeycloakAuthenticationProcessingFilter;
import org.keycloak.quickstart.springboot.components.CustomKeycloakLogoutHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Application security configuration.
 *
 */
@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
        grantedAuthorityMapper.setPrefix("ROLE_");
        grantedAuthorityMapper.setConvertToUpperCase(true);
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(grantedAuthorityMapper);
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    
    @Autowired
    public KeycloakClientRequestFactory keycloakClientRequestFactory;
    
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        return new KeycloakRestTemplate(keycloakClientRequestFactory);
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .csrf()
                .requireCsrfProtectionMatcher(this.keycloakCsrfRequestMatcher())
                .and()
                .sessionManagement()
                .sessionAuthenticationStrategy(this.sessionAuthenticationStrategy())
                .and()
                .addFilterBefore(this.keycloakPreAuthActionsFilter(), LogoutFilter.class)
                .addFilterBefore(this.keycloakAuthenticationProcessingFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(this.keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter.class)
                .addFilterAfter(this.keycloakAuthenticatedActionsRequestFilter(), KeycloakSecurityContextRequestFilter.class)
                .exceptionHandling().authenticationEntryPoint(this.authenticationEntryPoint())
                .and()
                .logout().addLogoutHandler(this.keycloakLogoutHandler())
                .logoutUrl("/sso/logout").permitAll()
                .logoutSuccessHandler(logoutSuccessHandler())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/products*").hasRole("USER")
                .anyRequest().permitAll();

    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandler(){
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.setContentType("application/json");
                PrintWriter out = response.getWriter();
                out.print("{}");
                out.flush();
            }
        };
//        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) ->{
//            response.setContentType("application/json");
//            PrintWriter out = response.getWriter();
//            out.print("{}");
//            out.flush();
//        };
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy();
    }

    //////////////

    protected CustomKeycloakLogoutHandler keycloakLogoutHandler() throws Exception {
        return new CustomKeycloakLogoutHandler(adapterDeploymentContext());
    }

    //@TODO Find out why AbstractAuthenticationProcessingFilter is being called twice.
    // This most probably is happening due to its decleration as a Bean in superclass
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() throws Exception {
        CustomKeycloakAuthenticationProcessingFilter filter = new CustomKeycloakAuthenticationProcessingFilter(authenticationManagerBean());
        filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
        return filter;
    }

    /////////////


}
