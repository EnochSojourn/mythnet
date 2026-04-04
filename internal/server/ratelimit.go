package server

import (
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // tokens per interval
	interval time.Duration
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

func newRateLimiter(requestsPerMinute int) *rateLimiter {
	rl := &rateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     requestsPerMinute,
		interval: time.Minute,
	}
	// Cleanup stale buckets every 5 minutes
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range rl.buckets {
				if b.lastFill.Before(cutoff) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{tokens: rl.rate, lastFill: time.Now()}
		rl.buckets[ip] = b
	}

	// Refill tokens based on elapsed time
	elapsed := time.Since(b.lastFill)
	if elapsed >= rl.interval {
		b.tokens = rl.rate
		b.lastFill = time.Now()
	} else {
		refill := int(float64(rl.rate) * (elapsed.Seconds() / rl.interval.Seconds()))
		b.tokens = min(b.tokens+refill, rl.rate)
		if refill > 0 {
			b.lastFill = time.Now()
		}
	}

	if b.tokens <= 0 {
		return false
	}

	b.tokens--
	return true
}

func rateLimitMiddleware(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for static assets
			if r.URL.Path == "/metrics" || r.URL.Path == "/topology.svg" {
				next.ServeHTTP(w, r)
				return
			}

			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
				ip = fwd
			}

			if !rl.allow(ip) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
