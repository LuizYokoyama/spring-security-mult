package io.github.luizyokoyama.springsecuritymult.config;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


@Configuration
public class MultipleAuthProvidersSecurityConfig {

    @Autowired
    CustomAuthenticationProvider customAuthProvider;
    @Autowired
    CustomAuthenticationProvider2 customAuthProvider2;
    @Autowired
    CustomAuthenticationProvider3 customAuthProvider3;

    @Autowired
    CustomAuthenticationProviderJwt customAuthenticationProviderJwt;

    @Bean
    public AuthenticationManager authManager(ObjectPostProcessor<Object> objectPostProcessor) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder(objectPostProcessor);
        authenticationManagerBuilder.authenticationProvider(customAuthProvider);
        authenticationManagerBuilder.authenticationProvider(customAuthProvider2);
        authenticationManagerBuilder.authenticationProvider(customAuthProvider3);
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProviderJwt);
        authenticationManagerBuilder.inMemoryAuthentication()
                .withUser("memuser")
                .password(passwordEncoder().encode("pass"))
                .roles("USER");
        return authenticationManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authManager) throws Exception {

        http.httpBasic(Customizer.withDefaults());
        http.oauth2ResourceServer(oauth-> oauth.jwt(Customizer.withDefaults()));

        //http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.csrf(csrf -> csrf.disable());
        //http.formLogin( form -> form.disable());

        http.authorizeHttpRequests(accessManagement -> accessManagement
                .requestMatchers("/api/**").authenticated()
        );
        http.authenticationManager(authManager);


        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    static public JwtDecoder jwtDecoder() {

        String publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0EpvmoIwzmwCpZzBHnqdXELtLEIfDaSdBKc5+7ywRvobpSBQ8M3RB0/Kbu/DRDCMdawxLo7mKfkPnf00hT5Ikbf765YtEAmCTNHQPoDoRXmJZt31HtV7bEXaUfFHGOM8oNEsv0T9M6G4luTHOH2BB5cChSRrSrLsS8UPUbRmlxpPspoEklkLhugTaUR5fPm3oliHj2+uhPwHBkIkbnBmRwdRbhbR3finxpmM+znQRSccT8Xb8GoQp9TqDb9EREuFVU2Aiceg4dvOEzBnxnadb0yvVOIAbUzSeYrawkPDI8kIGoi/RzJ4A0O4K0h1usvYZJOR3fL+gffX57WdV3mJqwIDAQAB" ;
        RSAPublicKey rsaPublicKey;
        byte[] encoded = Base64.decodeBase64(publicKeyStr);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
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