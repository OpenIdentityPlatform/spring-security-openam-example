package org.openidentityplatform.openamsecured.configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class OpenAmAuthenticationManager implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(authentication instanceof OpenAmAuthenticationToken) {
            authentication.setAuthenticated(true);
            return authentication;
        }
        authentication.setAuthenticated(false);
        return authentication;
    }
}
