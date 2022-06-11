package org.example.security;

import lombok.extern.slf4j.Slf4j;
import org.example.config.RestTemplateLoggingInterceptor;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.util.List;

@Slf4j
@Component
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @PostConstruct
    public void postConstruct() {
        var restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.setInterceptors(List.of(new RestTemplateLoggingInterceptor()));
        delegate.setRestOperations(restTemplate);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser");
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        log.info("accessToken: " + accessToken.getTokenValue());

        // Delegate to the default implementation for loading a user
        var oauth2User1 = delegate.loadUser(userRequest);

//        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        var oauth2User2 = new DefaultOAuth2User(oauth2User1.getAuthorities(), oauth2User1.getAttributes(), "sub");
        return oauth2User2;
    }
}
