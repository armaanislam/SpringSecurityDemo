package com.armaan.springsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.armaan.springsecuritydemo.security.ApplicationUserPermission.*;
import static com.armaan.springsecuritydemo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // Needed in case of Annotation based permission 
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
                // Order matters here
                .csrf().disable()
                .authorizeRequests() // We must authorize requests
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() // White listing some URLs that we don't need to sign to view // Permit the ant matcher listings
                .antMatchers("/api/**").hasRole(STUDENT.name()) // Roles allowed for the above API
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermissions())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermissions()) // Permissions allowed for the above API
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermissions())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
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
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails josephUser = User.builder()
                .username("Joseph")
                .password(passwordEncoder.encode("456"))
//                .roles(ADMIN.name()) // ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
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
    // We use authority to define permissions
}
