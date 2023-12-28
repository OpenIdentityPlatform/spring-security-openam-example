package org.openidentityplatform.openamsecured.configuration;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

public class OpenAmAuthenticationToken extends AbstractAuthenticationToken {
    private final String username;

    public OpenAmAuthenticationToken(String username) {
        super(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        this.username = username;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}
