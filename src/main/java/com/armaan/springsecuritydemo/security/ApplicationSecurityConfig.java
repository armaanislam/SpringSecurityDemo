package com.armaan.springsecuritydemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    // By default, we get form based authentication; Now we are implementing Basic Authentication
    // There is no way to log out from basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception { // Method for defining Basic Auth
        http
                .authorizeRequests() // We must authorize requests
                .antMatchers("/", "index", "/css/*", "/js/*") // White listing some URLs that we don't need to sign to view
                .permitAll() // Permit the ant matcher listings
                .anyRequest() // Any request must be authenticated
                .authenticated() // Any request must be authenticated; User must provide details
                .and()
                .httpBasic(); // Basic authentication mechanism that is being followed to authenticate user identity
    }

    @Override
    @Bean // To instantiate this method
    protected UserDetailsService userDetailsService() { // Method for defining Application User
        UserDetails armaanUser = User.builder() // User from Spring Framework Security
                .username("armaan")
                .password("123")
                .roles("STUDENT") // ROLE_STUDENT
                .build();
        return new InMemoryUserDetailsManager(
                armaanUser
        );
    }
}
