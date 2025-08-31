package com.example.rbac.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RoleTestController {

    @GetMapping("/api/admin/ping")
    public String adminPing() {
        return "Hello ADMIN!";
    }

    @GetMapping("/api/ops/ping")
    public String opsPing() {
        return "Hello OPS_USER!";
    }

    @GetMapping("/api/employee/ping")
    public String employeePing() {
        return "Hello EMPLOYEE!";
    }

    @GetMapping("/api/common/hello")
    public String common() {
        return "Hello authenticated user (any role)!";
    }
}
