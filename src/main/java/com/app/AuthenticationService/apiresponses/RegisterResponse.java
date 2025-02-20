package com.app.AuthenticationService.apiresponses;

public class RegisterResponse {
    public RegisterResponse(String message, int statusCode) {
        this.message = message;
        this.statusCode = statusCode;
    }

    private String message;
    private int statusCode;

}
