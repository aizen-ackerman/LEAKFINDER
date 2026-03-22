package com.leakfinder.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.io.Serializable;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        System.err.println("[JwtAuthenticationEntryPoint] Unauthorized access to: " + request.getRequestURI());
        System.err.println("[JwtAuthenticationEntryPoint] Exception: " + authException.getMessage());
        System.err.println("[JwtAuthenticationEntryPoint] Please ensure CLERK_PUBLISHABLE_KEY environment variable is set.");
        
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"Unauthorized. Please login again using Clerk.\"}");
    }
}