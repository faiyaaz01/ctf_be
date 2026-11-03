package com.ctf.platform.dto;

import lombok.Data;

public class AuthDto {

    @Data
    public static class LoginRequest {
        private String usernameOrEmail;
        private String password;
    }

    @Data
    public static class RegisterRequest {
        private String username;
        private String email;
        private String password;
    }

    @Data
    public static class AuthResponse {
        private String token;
        private String type = "Bearer";
        private String id;
        private String username;
        private String email;
        private Object roles;

        public AuthResponse(String token, String id, String username, String email, Object roles) {
            this.token = token;
            this.id = id;
            this.username = username;
            this.email = email;
            this.roles = roles;
        }
    }
}
