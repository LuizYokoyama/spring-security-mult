package io.github.luizyokoyama.springsecuritymult.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;

@Component
public class CustomAuthenticationProviderJwt implements AuthenticationProvider {

    String secret = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg18YCYu2jfu+EjR/Co9lu3GqP60jjUoL6aIzHrh1esQGhRANCAATlwYYsldCef9ycjdGNKbQWVbL/K8g0I8v9Jfm2nfvXE7kX9xCrg6HHkwMh9eC1o0CHazmxxi9pgh3xo2MdEBcO" ;
    private JwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(new SecretKeySpec(secret.getBytes(), SignatureAlgorithm.ES256.getName())).build();
    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();


/*
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken)authentication;
        Jwt jwt = this.getJwt(bearer);
        AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwt);
        if (token.getDetails() == null) {
            token.setDetails(bearer.getDetails());
        }

        return token;
    }
*/

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {

            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            return new UsernamePasswordAuthenticationToken("user4", "pass", authorities);

    }

    private Jwt getJwt(BearerTokenAuthenticationToken bearer) {
        try {
            return this.jwtDecoder.decode(bearer.getToken());
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
