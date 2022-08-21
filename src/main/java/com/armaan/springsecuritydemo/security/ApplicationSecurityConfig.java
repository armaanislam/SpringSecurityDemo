package com.armaan.springsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // By default, we get form based authentication; Now we are implementing Basic Authentication
    // There is no way to log out from basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception { // Method for defining Basic Auth
        http
                .authorizeRequests() // We must authorize requests
                .antMatchers("/", "index", "/css/*", "/js/*") // White listing some URLs that we don't need to sign to view
                .permitAll() // Permit the ant matcher listings
                .antMatchers("/api/**")
                .hasRole(ApplicationUserRole.STUDENT.name()) // Roles allowed for the above API
                .anyRequest() // Any request must be authenticated
                .authenticated() // Any request must be authenticated; User must provide details
                .and()
                .httpBasic(); // Basic authentication mechanism that is being followed to authenticate user identity
    }

    @Override
    @Bean // To instantiate this method
    protected UserDetailsService userDetailsService() { // Method for defining Application User
        UserDetails armaanUser = User.builder() // User from Spring Framework Security
                .username("Armaan")
                .password(passwordEncoder.encode("123"))
                .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                .build();

        UserDetails josephUser = User.builder()
                .username("Joseph")
                .password(passwordEncoder.encode("456"))
                .roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
                .build();

        UserDetails tomUser = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("123"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
                .build();

        return new InMemoryUserDetailsManager( // In Memory Database where all the user information is stored, the default user also remains stored here
                armaanUser,
                josephUser,
                tomUser
        );
    }

    // Role: Higher level few; Role consists of many permissions
    // Permission: Permission on specific things like Read, Write, APIs
    // An user can have multiple roles
}
