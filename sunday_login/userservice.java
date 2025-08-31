package com.example.rbac.service;

import com.example.rbac.dto.RegisterRequest;
import com.example.rbac.entity.Role;
import com.example.rbac.entity.User;
import com.example.rbac.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public User register(RegisterRequest req) {
        if (userRepository.existsByUsername(req.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        Role role;
        try {
            role = Role.valueOf(req.getRole());
        } catch (Exception e) {
            throw new RuntimeException("Invalid role. Choose ADMIN, OPS_USER, or EMPLOYEE");
        }

        String hashed = passwordEncoder.encode(req.getPassword());
        User user = new User(req.getUsername(), hashed, role);
        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public boolean checkPassword(String raw, String encoded) {
        return passwordEncoder.matches(raw, encoded);
    }
}
