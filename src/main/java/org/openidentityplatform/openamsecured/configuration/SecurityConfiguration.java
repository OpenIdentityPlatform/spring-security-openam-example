package org.openidentityplatform.openamsecured.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


//    @Bean
//    @Order(1)
//    public SecurityFilterChain securityWebFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/", "/oauth2/**")
//                        .permitAll()
//                        .requestMatchers("/protected-oauth").authenticated())
//                .oauth2Login(Customizer.withDefaults()).oauth2Client(Customizer.withDefaults()
//                );
//        return http.build();
//    }

//    @Bean
//    @Order(2)
//    public SecurityFilterChain securitySamlFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/")
//                        .permitAll()
//                        .requestMatchers("/protected-saml").authenticated())
//                .saml2Metadata(withDefaults())
//                .saml2Login(withDefaults())
//                .saml2Logout(withDefaults());
//        return http.build();
//    }

    @Bean
    @Order(3)
    public SecurityFilterChain securityOpenAmFilterChain(HttpSecurity http, AuthenticationConfiguration authConfig) throws Exception {
        http.addFilterAt(new OpenAmAuthenticationFilter(), RememberMeAuthenticationFilter.class)
                .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/", "/error")
                .permitAll()
                        .requestMatchers("/protected-openam").authenticated())
                .exceptionHandling(e ->
                        e.authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/openam-auth")));
        return http.build();
    }


}


