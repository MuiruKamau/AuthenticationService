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
    /*public ResponseEntity<?> registerUser(@RequestBody User user) {
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok().body(new ApiResponse(null, "Registration successful", HttpStatus.OK.value()));
    }*/

    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto registrationDto) {
        // Map the DTO to the User entity
        User user = new User();
        user.setUsername(registrationDto.getUsername());
        user.setFirstname(registrationDto.getFirstname());
        user.setLastname(registrationDto.getLastname());
        user.setEmail(registrationDto.getEmail());
        // Encrypt the password before saving
        user.setPassword(new BCryptPasswordEncoder().encode(registrationDto.getPassword()));

        userRepository.save(user);
        return ResponseEntity.ok().body(new ApiResponse(null, "Registration successful", HttpStatus.OK.value()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequestDto authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
    /*public ResponseEntity<?> authenticateUser(@RequestBody User request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));*/
        String token = jwtUtil.generateToken(authRequest.getUsername());
        return ResponseEntity.ok().body(new ApiResponse(token, "login successful", HttpStatus.OK.value()));
    }
        /*String token = jwtUtil.generateToken(request.getUsername());
        return ResponseEntity.ok().body(new ApiResponse(token,"login successful", HttpStatus.OK.value()));
    }*/
}