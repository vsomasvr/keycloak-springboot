package org.keycloak.quickstart.springboot.components;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.HttpServletRequest;

import static org.keycloak.constants.AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE;

public class CookieRequestMatcher implements RequestMatcher {

    public boolean matches(HttpServletRequest request) {
        return WebUtils.getCookie(request, KEYCLOAK_ADAPTER_STATE_COOKIE) !=null;
    }
}
