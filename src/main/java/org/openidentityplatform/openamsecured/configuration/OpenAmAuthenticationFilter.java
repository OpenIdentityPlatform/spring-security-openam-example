package org.openidentityplatform.openamsecured.configuration;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

public class OpenAmAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final String openAmUrl = "http://openam.example.org:8080/openam";
    private final String openAuthUrl = openAmUrl.concat("/XUI/#login");

    private final String openAmUserInfoUrl = openAmUrl.concat("/json/users?_action=idFromSession");
    private final String openAmCookieName = "iPlanetDirectoryPro";

    private final String redirectUrl = "http://app.example.org:8081/protected-openam";

    public OpenAmAuthenticationFilter() {
        super("/openam-auth", new OpenAmAuthenticationManager());
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
    }

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        Optional<Cookie> openamCookie = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(openAmCookieName)).findFirst();
        if(openamCookie.isEmpty()) {
           response.sendRedirect(openAuthUrl + "&goto=" + URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8));
           return null;
        } else {
            String userId = getUserIdFromSession(openamCookie.get().getValue());
            OpenAmAuthenticationToken token = new OpenAmAuthenticationToken(userId);
            token.setDetails(authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(token);
        }
    }

    protected String getUserIdFromSession(String sessionId) {
        RestTemplate restTemplate = new RestTemplate();
        ParameterizedTypeReference<Map<String, String>> responseType =
                new ParameterizedTypeReference<>() {};
        HttpHeaders headers = new HttpHeaders();
        headers.add(openAmCookieName, sessionId);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<?> entity = new HttpEntity<>(headers);
        ResponseEntity<Map<String, String>> response = restTemplate.exchange(openAmUserInfoUrl, HttpMethod.POST, entity, responseType);
        Map<String, String> body = response.getBody();
        return body.get("id");
    }

}
