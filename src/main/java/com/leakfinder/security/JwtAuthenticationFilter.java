package com.leakfinder.security;

import com.leakfinder.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private com.leakfinder.service.UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null) {
                try {
                    String username = jwtUtil.extractUsername(jwt);
                    UserDetails userDetails = null;
                    try {
                        userDetails = userDetailsService.loadUserByUsername(username);
                    } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
                        // User not in local DB — likely a Clerk token; skip internal JWT auth
                        System.err.println("[JwtAuthenticationFilter] User not in local DB (Clerk token?), skipping: " + username);
                    }
                    
                    if (userDetails != null && jwtUtil.validateToken(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        System.err.println("[JwtAuthenticationFilter] Successfully set authentication for user: " + username);
                    } else if (userDetails != null) {
                        System.err.println("[JwtAuthenticationFilter] Token validation failed for user: " + username);
                    }
                } catch (Exception e) {
                    System.err.println("[JwtAuthenticationFilter] Error processing JWT: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("[JwtAuthenticationFilter] Cannot set user authentication: " + e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            String token = headerAuth.substring(7);
            System.err.println("[JwtAuthenticationFilter] Extracted JWT from Authorization header");
            return token;
        }
        return null;
    }
}