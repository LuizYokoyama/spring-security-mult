package io.github.luizyokoyama.springsecuritymult.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


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






}