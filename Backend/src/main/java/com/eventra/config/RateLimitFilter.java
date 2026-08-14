package com.eventra.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long IDLE_TIMEOUT_MS = 10 * 60 * 1000L;
    private static final long EVICTION_INTERVAL_MS = 60_000L;
    private static final int MAX_BUCKETS = 100_000;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAccess = new ConcurrentHashMap<>();
    private final AtomicLong lastEvictionMillis = new AtomicLong(0L);

    private Bucket createNewBucket() {
        Bandwidth limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (path != null && path.matches("^/api/hackathons/[^/]+/register$") && "POST".equalsIgnoreCase(request.getMethod())) {
            long now = System.currentTimeMillis();
            maybeEvictIdleBuckets(now);
            String clientIp = getClientIp(request);
            Bucket bucket = buckets.computeIfAbsent(clientIp, k -> {
                lastAccess.put(k, now);
                return createNewBucket();
            });
            lastAccess.put(clientIp, now);

            if (!bucket.tryConsume(1)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Too Many Requests\", \"message\": \"Rate limit exceeded. Try again in a minute.\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void maybeEvictIdleBuckets(long now) {
        long lastEviction = lastEvictionMillis.get();
        if (now - lastEviction <= EVICTION_INTERVAL_MS) {
            return;
        }
        if (!lastEvictionMillis.compareAndSet(lastEviction, now)) {
            return;
        }
        long minAgeMs = buckets.size() > MAX_BUCKETS ? EVICTION_INTERVAL_MS : IDLE_TIMEOUT_MS;
        Iterator<Map.Entry<String, Long>> it = lastAccess.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> entry = it.next();
            if (now - entry.getValue() > minAgeMs) {
                buckets.remove(entry.getKey());
                it.remove();
            }
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
