package com.app.AuthenticationService.dto;

import com.app.AuthenticationService.model.Role;
import lombok.Data;

import java.util.Set;

@Data
public class RoleAssignmentDto {
    private String username;
    private Set<Role> roles;
}
