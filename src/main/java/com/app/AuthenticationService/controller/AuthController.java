package com.app.AuthenticationService.controller;

import com.app.AuthenticationService.apiresponses.ApiResponse;
import com.app.AuthenticationService.dto.AuthenticationRequestDto;
import com.app.AuthenticationService.dto.UserRegistrationDto;
import com.app.AuthenticationService.model.User;
import com.app.AuthenticationService.apiresponses.RegisterResponse;
import com.app.AuthenticationService.repository.UserRepository;
import com.app.AuthenticationService.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.app.AuthenticationService.dto.RoleAssignmentDto; // Import RoleAssignmentDto
import com.app.AuthenticationService.model.Role; // Import Role
import org.springframework.security.access.prepost.PreAuthorize; // Import PreAuthorize
import java.util.Optional;
import java.util.HashSet; // Import HashSet if not already imported
import java.util.Set;      // Import Set if not already imported

@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto registrationDto) {
        User user = new User();
        user.setUsername(registrationDto.getUsername());
        user.setFirstname(registrationDto.getFirstname());
        user.setLastname(registrationDto.getLastname());
        user.setEmail(registrationDto.getEmail());
        user.setPassword(new BCryptPasswordEncoder().encode(registrationDto.getPassword()));

        // No need to set roles from registrationDto anymore, users are registered without roles initially

        userRepository.save(user);
        return ResponseEntity.ok().body(new ApiResponse(null, "Registration successful. Awaiting role assignment.", HttpStatus.OK.value())); // Updated message
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequestDto authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        String token = jwtUtil.generateToken(authRequest.getUsername());
        return ResponseEntity.ok().body(new ApiResponse(token, "login successful", HttpStatus.OK.value()));
    }
    @GetMapping("/admin/dashboard")
    public ResponseEntity<?> adminDashboard() {
        return ResponseEntity.ok(new ApiResponse(null, "Admin Dashboard - Admin Role Required", HttpStatus.OK.value()));
    }

    @GetMapping("/teacher/courses")
    public ResponseEntity<?> teacherCourses() {
        return ResponseEntity.ok(new ApiResponse(null, "Teacher Courses - Teacher or Admin Role Required", HttpStatus.OK.value()));
    }

    @GetMapping("/student/profile")
    public ResponseEntity<?> studentProfile() {
        return ResponseEntity.ok(new ApiResponse(null, "Student Profile - Student, Teacher, or Admin Role Required", HttpStatus.OK.value()));
    }

    @GetMapping("/public") // Example public endpoint for testing
    public ResponseEntity<?> publicEndpoint() {
        return ResponseEntity.ok(new ApiResponse(null, "Public Endpoint - No Authentication Required", HttpStatus.OK.value()));
    }

    // New endpoint for assigning roles - Only SUPER_ADMINISTRATOR can access
    @PostMapping("/admin/assign-role")
    @PreAuthorize("hasRole('SUPER_ADMINISTRATOR')") // Secure this endpoint for SUPER_ADMINISTRATOR
    public ResponseEntity<?> assignRole(@RequestBody RoleAssignmentDto roleAssignmentDto) {
        Optional<User> userOptional = userRepository.findByUsername(roleAssignmentDto.getUsername());
        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new RegisterResponse("User not found", HttpStatus.NOT_FOUND.value()));
        }

        User user = userOptional.get();
        user.setRoles(roleAssignmentDto.getRoles()); // Update user roles
        userRepository.save(user);

        return ResponseEntity.ok(new ApiResponse(null, "Roles assigned successfully to user: " + user.getUsername(), HttpStatus.OK.value()));
    }
}