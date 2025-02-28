package com.app.AuthenticationService.dto;

import lombok.Data;

@Data
public class UserRegistrationDto {
    private String username;
    private String firstname;
    private String lastname;
    private String password;
    private String email;
    // Removed: private Set<Role> roles;
}