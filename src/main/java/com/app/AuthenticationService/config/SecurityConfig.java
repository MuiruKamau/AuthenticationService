package com.app.AuthenticationService.config;

import com.app.AuthenticationService.security.CustomUserDetailsService;
import com.app.AuthenticationService.security.JwtAuthenticationFilter;
import com.app.AuthenticationService.security.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@SuppressWarnings("ALL")
@Configuration
public class SecurityConfig {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public AuthenticationManager authenticationManager(CustomUserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "http://localhost:8081/swagger-ui/index.html",
                                "/auth/register", // Make sure register is permitted
                                "/auth/login",
                                "/auth/public"

                                // Make sure login is permitted
                        ).permitAll()
                        // Example Role-Based Access Control rules:
                        .requestMatchers("/auth/admin/**").hasRole("ADMINISTRATOR") // Only ADMIN role can access /auth/admin/**
                        .requestMatchers("/auth/teacher/courses").hasAnyRole("TEACHER", "ADMINISTRATOR") // TEACHER or ADMIN can access /auth/teacher/**
                        .requestMatchers("/auth/student/**").hasAnyRole("STUDENT", "TEACHER", "ADMINISTRATOR") // STUDENT, TEACHER, or ADMIN can access /auth/student/**
                        .anyRequest().authenticated() // All other /auth/** endpoints require authentication
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}