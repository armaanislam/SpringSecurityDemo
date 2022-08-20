package com.armaan.springsecuritydemo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    // By default we get form based authentication; Now we are implementing Basic Authentication
    // There is no way to log out from basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // We must authorize requests
                .anyRequest() // Any request must be authenticated
                .authenticated() // Any request must be authenticated; User must provide details
                .and()
                .httpBasic(); // Basic authentication mechanism that is being followed to authenticate user identity
    }
}
