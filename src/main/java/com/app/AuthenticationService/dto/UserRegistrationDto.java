package com.app.AuthenticationService.dto;

import com.app.AuthenticationService.model.Role;
import lombok.Data;

import java.util.Set;

@Data
public class UserRegistrationDto {
    private String username;
    private String firstname;
    private String lastname;
    private String password;
    private String email;
    private Set<Role> roles;
}
