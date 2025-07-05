// Package ratelimit - Redis backend implementation
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisBackend implements the Backend interface using Redis storage
type RedisBackend struct {
	client *redis.Client
	config RedisConfig
}

// NewRedisBackend creates a new Redis backend
func NewRedisBackend(config RedisConfig) (*RedisBackend, error) {
	// Set defaults
	if config.PoolSize <= 0 {
		config.PoolSize = 10
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 3 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 3 * time.Second
	}
	if config.KeyPrefix == "" {
		config.KeyPrefix = "hockeypuck:ratelimit:"
	}
	if config.TTL <= 0 {
		config.TTL = 24 * time.Hour
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		MaxRetries:   config.MaxRetries,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisBackend{
		client: client,
		config: config,
	}, nil
}

// Redis key generation helpers
func (r *RedisBackend) connectionKey(ip string) string {
	return r.config.KeyPrefix + "conn:" + ip
}

func (r *RedisBackend) requestKey(ip string) string {
	return r.config.KeyPrefix + "req:" + ip
}

func (r *RedisBackend) errorKey(ip string) string {
	return r.config.KeyPrefix + "err:" + ip
}

func (r *RedisBackend) banKey(ip string) string {
	return r.config.KeyPrefix + "ban:" + ip
}

func (r *RedisBackend) torExitKey() string {
	return r.config.KeyPrefix + "tor:exits"
}

func (r *RedisBackend) torMetaKey() string {
	return r.config.KeyPrefix + "tor:meta"
}

func (r *RedisBackend) globalTorKey() string {
	return r.config.KeyPrefix + "tor:global"
}

// Connection tracking methods

func (r *RedisBackend) GetConnectionCount(ip string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	val, err := r.client.Get(ctx, r.connectionKey(ip)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get connection count: %w", err)
	}

	count, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("invalid connection count value: %w", err)
	}

	return count, nil
}

func (r *RedisBackend) IncrementConnectionCount(ip string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.connectionKey(ip)

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment connection count: %w", err)
	}

	return nil
}

func (r *RedisBackend) DecrementConnectionCount(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.connectionKey(ip)

	// Use Lua script to ensure we don't go below zero
	script := `
		local current = redis.call('GET', KEYS[1])
		if current and tonumber(current) > 0 then
			return redis.call('DECR', KEYS[1])
		else
			redis.call('DEL', KEYS[1])
			return 0
		end
	`

	_, err := r.client.Eval(ctx, script, []string{key}).Result()
	if err != nil {
		return fmt.Errorf("failed to decrement connection count: %w", err)
	}

	return nil
}

// Request rate tracking methods

func (r *RedisBackend) GetRequestCount(ip string, window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.requestKey(ip)
	now := time.Now()
	minTime := now.Add(-window)

	// Use sorted set with timestamps as scores
	count, err := r.client.ZCount(ctx, key, strconv.FormatInt(minTime.UnixNano(), 10), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get request count: %w", err)
	}

	return int(count), nil
}

func (r *RedisBackend) IncrementRequestCount(ip string, window time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.requestKey(ip)
	now := time.Now()
	nowNano := now.UnixNano()
	minTime := now.Add(-window)
	minTimeNano := minTime.UnixNano()

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Remove old entries
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(minTimeNano, 10))

	// Add current request
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(nowNano),
		Member: nowNano, // Use timestamp as both score and member
	})

	// Set expiration
	pipe.Expire(ctx, key, window*2) // Keep for twice the window duration

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment request count: %w", err)
	}

	return nil
}

// Error rate tracking methods

func (r *RedisBackend) GetErrorCount(ip string, window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.errorKey(ip)
	now := time.Now()
	minTime := now.Add(-window)

	count, err := r.client.ZCount(ctx, key, strconv.FormatInt(minTime.UnixNano(), 10), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get error count: %w", err)
	}

	return int(count), nil
}

func (r *RedisBackend) IncrementErrorCount(ip string, window time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.errorKey(ip)
	now := time.Now()
	nowNano := now.UnixNano()
	minTime := now.Add(-window)
	minTimeNano := minTime.UnixNano()

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Remove old entries
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(minTimeNano, 10))

	// Add current error
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(nowNano),
		Member: nowNano,
	})

	// Set expiration
	pipe.Expire(ctx, key, window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment error count: %w", err)
	}

	return nil
}

// Ban management methods

func (r *RedisBackend) IsBanned(ip string) (bool, time.Time, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.banKey(ip)

	// Use hash to store ban information
	fields, err := r.client.HMGet(ctx, key, "expires_at", "reason").Result()
	if err != nil {
		return false, time.Time{}, "", fmt.Errorf("failed to check ban status: %w", err)
	}

	// Check if ban exists
	if fields[0] == nil {
		return false, time.Time{}, "", nil
	}

	// Parse expiration time
	expiresAtStr, ok := fields[0].(string)
	if !ok {
		return false, time.Time{}, "", fmt.Errorf("invalid expires_at value")
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtStr)
	if err != nil {
		return false, time.Time{}, "", fmt.Errorf("invalid expires_at format: %w", err)
	}

	// Check if ban has expired
	if time.Now().After(expiresAt) {
		// Clean up expired ban asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
			defer cancel()
			r.client.Del(ctx, key)
		}()
		return false, time.Time{}, "", nil
	}

	// Get reason
	reason := ""
	if fields[1] != nil {
		if reasonStr, ok := fields[1].(string); ok {
			reason = reasonStr
		}
	}

	return true, expiresAt, reason, nil
}

func (r *RedisBackend) BanIP(ip string, duration time.Duration, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.banKey(ip)
	expiresAt := time.Now().Add(duration)

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Set ban information
	pipe.HMSet(ctx, key, map[string]interface{}{
		"expires_at": expiresAt.Format(time.RFC3339Nano),
		"reason":     reason,
		"banned_at":  time.Now().Format(time.RFC3339Nano),
	})

	// Set expiration slightly longer than ban duration
	pipe.Expire(ctx, key, duration+time.Hour)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to ban IP: %w", err)
	}

	return nil
}

func (r *RedisBackend) UnbanIP(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.banKey(ip)

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to unban IP: %w", err)
	}

	return nil
}

// Tor exit node management methods

func (r *RedisBackend) IsTorExit(ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.torExitKey()

	isMember, err := r.client.SIsMember(ctx, key, ip).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check Tor exit status: %w", err)
	}

	return isMember, nil
}

func (r *RedisBackend) SetTorExits(ips []string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.torExitKey()
	metaKey := r.torMetaKey()

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Clear existing set
	pipe.Del(ctx, key)

	// Add new IPs
	if len(ips) > 0 {
		// Convert to interface slice
		members := make([]interface{}, len(ips))
		for i, ip := range ips {
			members[i] = ip
		}
		pipe.SAdd(ctx, key, members...)
	}

	// Set expiration
	pipe.Expire(ctx, key, ttl)

	// Update metadata
	pipe.HMSet(ctx, metaKey, map[string]interface{}{
		"updated_at": time.Now().Format(time.RFC3339Nano),
		"count":      len(ips),
	})
	pipe.Expire(ctx, metaKey, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set Tor exits: %w", err)
	}

	return nil
}

func (r *RedisBackend) GetTorExitCount() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.torExitKey()

	count, err := r.client.SCard(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get Tor exit count: %w", err)
	}

	return int(count), nil
}

// Global Tor rate limiting methods

func (r *RedisBackend) GetGlobalTorRequestCount(window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout)
	defer cancel()

	key := r.globalTorKey()
	now := time.Now()
	minTime := now.Add(-window)

	count, err := r.client.ZCount(ctx, key, strconv.FormatInt(minTime.UnixNano(), 10), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get global Tor request count: %w", err)
	}

	return int(count), nil
}

func (r *RedisBackend) IncrementGlobalTorRequestCount(window time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.WriteTimeout)
	defer cancel()

	key := r.globalTorKey()
	now := time.Now()
	nowNano := now.UnixNano()
	minTime := now.Add(-window)
	minTimeNano := minTime.UnixNano()

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Remove old entries
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(minTimeNano, 10))

	// Add current request
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(nowNano),
		Member: nowNano,
	})

	// Set expiration
	pipe.Expire(ctx, key, window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment global Tor request count: %w", err)
	}

	return nil
}

// Statistics methods

func (r *RedisBackend) GetStats() (BackendStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ReadTimeout*2)
	defer cancel()

	// Get Tor exit count and metadata
	torExitCount, _ := r.GetTorExitCount()

	torMeta, err := r.client.HMGet(ctx, r.torMetaKey(), "updated_at", "count").Result()
	torLastUpdate := time.Time{}
	if err == nil && torMeta[0] != nil {
		if updatedAtStr, ok := torMeta[0].(string); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, updatedAtStr); err == nil {
				torLastUpdate = parsed
			}
		}
	}

	// Count banned IPs by scanning ban keys
	pattern := r.config.KeyPrefix + "ban:*"
	var cursor uint64
	var totalBanned, torBanned int

	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			break
		}

		for _, key := range keys {
			// Extract IP from key
			parts := strings.Split(key, ":")
			if len(parts) < 3 {
				continue
			}
			ip := parts[len(parts)-1]

			// Check if ban is still valid
			if banned, _, _, err := r.IsBanned(ip); err == nil && banned {
				totalBanned++

				// Check if it's a Tor exit
				if isTor, err := r.IsTorExit(ip); err == nil && isTor {
					torBanned++
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// Count tracked IPs (rough estimate using key patterns)
	trackedIPs := 0
	patterns := []string{
		r.config.KeyPrefix + "conn:*",
		r.config.KeyPrefix + "req:*",
		r.config.KeyPrefix + "err:*",
	}

	uniqueIPs := make(map[string]bool)
	for _, pattern := range patterns {
		cursor = 0
		for {
			keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				break
			}

			for _, key := range keys {
				// Extract IP from key
				parts := strings.Split(key, ":")
				if len(parts) >= 3 {
					ip := parts[len(parts)-1]
					uniqueIPs[ip] = true
				}
			}

			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}
	}
	trackedIPs = len(uniqueIPs)

	return BackendStats{
		TrackedIPs:    trackedIPs,
		BannedIPs:     totalBanned,
		TorBanned:     torBanned,
		BackendType:   "redis",
		TorExitCount:  torExitCount,
		TorLastUpdate: torLastUpdate,
	}, nil
}

// Cleanup methods

func (r *RedisBackend) Cleanup(ctx context.Context) error {
	// Redis automatically handles TTL expiration, but we can clean up
	// old entries from sorted sets manually for efficiency

	patterns := []string{
		r.config.KeyPrefix + "req:*",
		r.config.KeyPrefix + "err:*",
		r.globalTorKey(),
	}

	for _, pattern := range patterns {
		var cursor uint64
		for {
			keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				break
			}

			// Clean up old entries from sorted sets
			cutoff := time.Now().Add(-time.Hour)
			cutoffNano := strconv.FormatInt(cutoff.UnixNano(), 10)

			pipe := r.client.Pipeline()
			for _, key := range keys {
				pipe.ZRemRangeByScore(ctx, key, "-inf", cutoffNano)
			}
			pipe.Exec(ctx)

			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}
	}

	return nil
}

// Close method

func (r *RedisBackend) Close() error {
	return r.client.Close()
}
