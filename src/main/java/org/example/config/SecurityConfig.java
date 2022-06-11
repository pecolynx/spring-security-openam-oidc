package org.example.config;

import lombok.RequiredArgsConstructor;
import org.example.security.CustomAuthenticationSuccessHandler;
import org.example.security.CustomOAuth2UserService;
import org.example.security.CustomOidcUserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    private final CustomOAuth2UserService customOAuth2UserService;

    private final CustomOidcUserService customOidcUserService;

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        var accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        var tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
        var restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.setInterceptors(List.of(new RestTemplateLoggingInterceptor()));

        accessTokenResponseClient.setRestOperations(restTemplate);
        return accessTokenResponseClient;
    }

    /*
    http://localhost:9000/private
    */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2Login()
                .successHandler(customAuthenticationSuccessHandler)
                .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient()).and()
                .userInfoEndpoint().userService(customOAuth2UserService).and()
                .userInfoEndpoint().oidcUserService(customOidcUserService).and()
                .and()
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        .mvcMatchers("/", "/public").permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }
}
