package httplog

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a per-IP token bucket. Buckets live in memory and reset
// on process restart — acceptable for the v1 single-VM deploy. A future
// multi-node setup would move this to Redis or a stickier load-balancer
// scheme; the call site signature stays the same.
//
// Token replenishment is inline (calculated on each Allow call from the
// elapsed time since the last refill) rather than driven by a background
// ticker. That keeps the implementation goroutine-free and means an idle
// IP costs nothing until it makes a request.
//
// Buckets are never evicted in this version. A burst of unique IPs (DDoS
// or shotgun scan) grows the map; at 24 bytes per bucket and millions of
// distinct attackers the cost is bounded for the lifetime of the process.
// Restart cleans the slate. If this becomes a problem before U10 lands,
// add a periodic janitor that drops buckets last-touched > ttl ago.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	// refillPerSecond is the steady-state replenishment rate (tokens per
	// second). For "N requests per minute" we use N/60.
	refillPerSecond float64
	now             func() time.Time
}

// bucket is the per-IP token state. tokens may be fractional during
// inter-tick refill.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter constructs a token bucket sized for perMinute requests
// per IP per minute. Each bucket starts full so the first perMinute
// requests from a fresh IP succeed.
func NewRateLimiter(perMinute int) *RateLimiter {
	return &RateLimiter{
		buckets:         make(map[string]*bucket),
		capacity:        float64(perMinute),
		refillPerSecond: float64(perMinute) / 60.0,
		now:             time.Now,
	}
}

// Allow returns true if the IP has tokens remaining and decrements one.
// Returns false if the bucket is empty (rate-limit the request).
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[ip]
	if !ok {
		// Fresh bucket: start full, consume one, store.
		rl.buckets[ip] = &bucket{tokens: rl.capacity - 1, lastSeen: now}
		return true
	}

	// Replenish based on elapsed time, cap at capacity.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(rl.capacity, b.tokens+elapsed*rl.refillPerSecond)
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RateLimitMiddleware wraps next with the supplied limiter keyed by client
// IP. On a denied request it emits 429 with a plain-text body and a
// Retry-After header indicating roughly when the next token will be
// available (1 minute, conservative).
//
// The middleware is intentionally narrow — apply it only to endpoints
// that need rate limiting (the two /auth/* paths), not the proxy hot
// path. Burning a token-bucket lookup per upstream request would add
// pointless serialization through the global limiter mutex.
func RateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !limiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited; try again in a minute\n"))
			FromContext(r.Context()).Warn("rate_limited",
				"path", r.URL.Path,
				"remote_addr", ip,
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}
