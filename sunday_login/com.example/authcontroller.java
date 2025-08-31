package com.example.rbac.controller;

import com.example.rbac.dto.AuthRequest;
import com.example.rbac.dto.AuthResponse;
import com.example.rbac.dto.RegisterRequest;
import com.example.rbac.entity.User;
import com.example.rbac.service.JwtService;
import com.example.rbac.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    // REGISTER
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        try {
            User user = userService.register(req);
            String token = jwtService.generateToken(user.getUsername(), user.getRole());
            return ResponseEntity.ok(new AuthResponse(token, user.getUsername(), user.getRole().name()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest req) {
        try {
            User user = userService.findByUsername(req.getUsername());
            if (!userService.checkPassword(req.getPassword(), user.getPassword())) {
                return ResponseEntity.status(401).body("{\"error\":\"Invalid credentials\"}");
            }
            String token = jwtService.generateToken(user.getUsername(), user.getRole());
            return ResponseEntity.ok(new AuthResponse(token, user.getUsername(), user.getRole().name()));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
