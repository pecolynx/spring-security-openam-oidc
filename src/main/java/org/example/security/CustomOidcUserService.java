package org.example.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.config.RestTemplateLoggingInterceptor;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService oidcUserService= new OidcUserService();
    private final CustomOAuth2UserService delegate;

    @PostConstruct
    public void postConstruct() {
        oidcUserService.setOauth2UserService(delegate);
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser");
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        log.info("accessToken: " + accessToken.getTokenValue());

        // Delegate to the default implementation for loading a user
        var oidcUser1 = oidcUserService.loadUser(userRequest);

//        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        var oidcUser2 = new DefaultOidcUser(oidcUser1.getAuthorities(), oidcUser1.getIdToken(),  oidcUser1.getUserInfo(),"sub");
        return oidcUser2;
    }

}
