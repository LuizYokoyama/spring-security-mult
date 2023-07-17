package io.github.luizyokoyama.springsecuritymult.config;


import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


@Component
public class CustomAuthenticationProviderJwt implements AuthenticationProvider {


    @Value("${my.jwt.public.key}")
    private String myPublicKey;

    @Value("${my.jwt.algorithm}")
    private String algorithm;

    private final Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();



    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AbstractAuthenticationToken token;
        BearerTokenAuthenticationToken bearer;
        try {
            bearer = (BearerTokenAuthenticationToken)authentication;
            Jwt jwt = this.getJwt(bearer);
            token = this.jwtAuthenticationConverter.convert(jwt);
        }catch (Exception e){
            throw new BadCredentialsException("JWT token authentication failed");
        }

        if (token == null){
            throw new BadCredentialsException("JWT token authentication failed");
        }
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

    @Bean
    public JwtDecoder jwtDecoder() {

        RSAPublicKey rsaPublicKey;
        byte[] encoded = Base64.decodeBase64(myPublicKey);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return  NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
    }

}
