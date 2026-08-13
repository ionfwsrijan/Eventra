package com.sandeep.eventrabackend.ratelimit;

import com.sandeep.eventrabackend.config.RateLimitProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

/**
 * Differentiates SSE Heartbeat Reconnect Streams from REST API Rate Limit Buckets.
 */
@Component("sseRateLimitingFilter")
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final RateLimitProperties properties;

    public RateLimitingFilter(RateLimitService rateLimitService, RateLimitProperties properties) {
        this.rateLimitService = rateLimitService;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String clientIp = getClientIp(request);

        // FIX (#13902): SSE stream reconnects use an isolated high-capacity bucket
        if (path != null && path.startsWith("/api/stream/")) {
            RateLimitResult result = rateLimitService.consume("sse-stream", clientIp, 1000, Duration.ofMinutes(1));
            if (!result.allowed()) {
                response.setStatus(429);
                response.setHeader("Retry-After", String.valueOf(result.retryAfterSeconds()));
                response.getWriter().write("Too many SSE reconnection pings.");
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        // Standard REST API Rate Limiting Bucket
        RateLimitResult result = rateLimitService.consume("rest-api", clientIp, 100, Duration.ofMinutes(1));
        if (!result.allowed()) {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(result.retryAfterSeconds()));
            response.getWriter().write("Rate limit exceeded. Please try again later.");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isEmpty()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
