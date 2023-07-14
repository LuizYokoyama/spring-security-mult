package io.github.luizyokoyama.springsecuritymult.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;

import static io.github.luizyokoyama.springsecuritymult.config.MultipleAuthProvidersSecurityConfig.jwtDecoder;


@Component
public class CustomAuthenticationProviderJwt implements AuthenticationProvider {


    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();



    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken)authentication;
        Jwt jwt = this.getJwt(bearer);
        AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwt);
        if (token.getDetails() == null) {
            token.setDetails(bearer.getDetails());
        }

        return token;
    }

    private Jwt getJwt(BearerTokenAuthenticationToken bearer) {
        try {
            return jwtDecoder().decode(bearer.getToken());
        } catch (BadJwtException badJwtException) {
            throw new InvalidBearerTokenException(badJwtException.getMessage(), badJwtException);
        } catch (JwtException jwtException) {
            throw new AuthenticationServiceException(jwtException.getMessage(), jwtException);
        }
    }

    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }


}
