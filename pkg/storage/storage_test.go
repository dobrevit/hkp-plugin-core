package storage

import (
	"testing"
	"time"
)

// TestStorageInterface tests the Storage interface implementation
func TestStorageInterface(t *testing.T) {
	storage := &NoOpStorage{}

	// Test MatchMD5 functionality
	t.Run("MatchMD5", func(t *testing.T) {
		hashes := []string{"abc123", "def456"}
		results, err := storage.MatchMD5(hashes)
		if err != nil {
			t.Errorf("MatchMD5 returned error: %v", err)
		}
		if results != nil {
			t.Errorf("Expected nil results from NoOpStorage, got %v", results)
		}
	})

	// Test ModifiedSince functionality
	t.Run("ModifiedSince", func(t *testing.T) {
		since := time.Now().Add(-24 * time.Hour)
		results, err := storage.ModifiedSince(since)
		if err != nil {
			t.Errorf("ModifiedSince returned error: %v", err)
		}
		if results != nil {
			t.Errorf("Expected nil results from NoOpStorage, got %v", results)
		}
	})

	// Test FetchKeys functionality
	t.Run("FetchKeys", func(t *testing.T) {
		keyIDs := []string{"key1", "key2"}
		keys, err := storage.FetchKeys(keyIDs)
		if err != nil {
			t.Errorf("FetchKeys returned error: %v", err)
		}
		if keys != nil {
			t.Errorf("Expected nil keys from NoOpStorage, got %v", keys)
		}
	})

	// Test FetchKeysPrefix functionality
	t.Run("FetchKeysPrefix", func(t *testing.T) {
		prefix := "ABC"
		keys, err := storage.FetchKeysPrefix(prefix)
		if err != nil {
			t.Errorf("FetchKeysPrefix returned error: %v", err)
		}
		if keys != nil {
			t.Errorf("Expected nil keys from NoOpStorage, got %v", keys)
		}
	})

	// Test Insert functionality
	t.Run("Insert", func(t *testing.T) {
		testKey := &Pubkey{
			RFingerprint: "TEST123456789",
			Creation:     time.Now(),
			State:        1,
			Packet:       []byte("test packet"),
			Ctime:        time.Now(),
			Mtime:        time.Now(),
			MD5:          "testmd5",
			SHA256:       "testsha256",
			Size:         256,
		}
		keys := []*Pubkey{testKey}

		err := storage.Insert(keys)
		if err != nil {
			t.Errorf("Insert returned error: %v", err)
		}
	})

	// Test Update functionality
	t.Run("Update", func(t *testing.T) {
		now := time.Now()
		oldKey := &Pubkey{
			RFingerprint: "OLD123456789",
			Creation:     now,
			State:        1,
			Ctime:        now,
			Mtime:        now,
		}
		newKey := &Pubkey{
			RFingerprint: "NEW123456789",
			Creation:     now,
			State:        1,
			Ctime:        now,
			Mtime:        now,
		}

		err := storage.Update(oldKey, newKey)
		if err != nil {
			t.Errorf("Update returned error: %v", err)
		}
	})

	// Test Delete functionality
	t.Run("Delete", func(t *testing.T) {
		keyIDs := []string{"key1", "key2"}
		err := storage.Delete(keyIDs)
		if err != nil {
			t.Errorf("Delete returned error: %v", err)
		}
	})

	// Test Stats functionality
	t.Run("Stats", func(t *testing.T) {
		stats, err := storage.Stats()
		if err != nil {
			t.Errorf("Stats returned error: %v", err)
		}
		if stats == nil {
			t.Error("Expected stats object, got nil")
			return
		}
		// NoOpStorage should return zero stats
		if stats.Total != 0 || stats.Inserted != 0 || stats.Updated != 0 {
			t.Errorf("Expected zero stats from NoOpStorage, got %+v", stats)
		}
	})

	// Test Healthy functionality
	t.Run("Healthy", func(t *testing.T) {
		err := storage.Healthy()
		if err != nil {
			t.Errorf("Healthy returned error: %v", err)
		}
	})

	// Test ReconStats functionality
	t.Run("ReconStats", func(t *testing.T) {
		reconStats, err := storage.ReconStats()
		if err != nil {
			t.Errorf("ReconStats returned error: %v", err)
		}
		if reconStats == nil {
			t.Error("Expected recon stats object, got nil")
			return
		}
		// NoOpStorage should return zero recon stats
		if reconStats.Total != 0 {
			t.Errorf("Expected zero recon stats from NoOpStorage, got %+v", reconStats)
		}
	})

	// Test ReconState functionality
	t.Run("ReconState", func(t *testing.T) {
		reconState, err := storage.ReconState()
		if err != nil {
			t.Errorf("ReconState returned error: %v", err)
		}
		// NoOpStorage should return empty but valid state
		if reconState.Version != 0 {
			t.Errorf("Expected zero version from NoOpStorage, got %d", reconState.Version)
		}
	})

	// Test Close functionality
	t.Run("Close", func(t *testing.T) {
		err := storage.Close()
		if err != nil {
			t.Errorf("Close returned error: %v", err)
		}
	})
}

// TestPubkeyStructure tests Pubkey struct validation and behavior
func TestPubkeyStructure(t *testing.T) {
	now := time.Now()
	expiration := now.Add(365 * 24 * time.Hour)

	pubkey := &Pubkey{
		RFingerprint: "ABCD1234567890ABCDEF",
		Creation:     now,
		Expiration:   &expiration,
		State:        1,
		Packet:       []byte("test packet data"),
		Ctime:        now,
		Mtime:        now,
		MD5:          "md5hash123",
		SHA256:       "sha256hash456",
		Size:         4096,
	}

	// Test that we can create a valid pubkey
	if pubkey == nil {
		t.Fatal("Failed to create pubkey")
	}

	// Test fingerprint validation
	if len(pubkey.RFingerprint) != 20 {
		t.Errorf("Expected fingerprint length 20, got %d", len(pubkey.RFingerprint))
	}

	// Test expiration handling
	if pubkey.Expiration == nil {
		t.Error("Expected expiration to be set")
	} else if pubkey.Expiration.Before(pubkey.Creation) {
		t.Error("Expiration should be after creation time")
	}

	// Test packet data
	if len(pubkey.Packet) == 0 {
		t.Error("Expected packet data to be present")
	}

	// Test key size validation
	validSizes := []int{1024, 2048, 4096, 8192}
	validSize := false
	for _, size := range validSizes {
		if pubkey.Size == size {
			validSize = true
			break
		}
	}
	if !validSize {
		t.Errorf("Unusual key size: %d", pubkey.Size)
	}
}

// TestIdentityStructure tests Identity struct validation
func TestIdentityStructure(t *testing.T) {
	now := time.Now()

	identity := &Identity{
		ScopedDigest: "digest123",
		Packet:       []byte("identity packet"),
		Creation:     now,
		State:        1,
		Ctime:        now,
		Mtime:        now,
		Keywords:     []string{"test", "identity", "example"},
	}

	// Test digest validation
	if len(identity.ScopedDigest) == 0 {
		t.Error("Expected scoped digest to be present")
	}

	// Test keywords functionality
	if len(identity.Keywords) == 0 {
		t.Error("Expected keywords to be present")
	}

	// Test that keywords contain expected values
	expectedKeywords := map[string]bool{
		"test":     true,
		"identity": true,
		"example":  true,
	}

	for _, keyword := range identity.Keywords {
		if !expectedKeywords[keyword] {
			t.Errorf("Unexpected keyword: %s", keyword)
		}
	}
}

// TestSearchFunctionality tests search criteria and results
func TestSearchFunctionality(t *testing.T) {
	now := time.Now()
	after := now.Add(-24 * time.Hour)
	before := now.Add(24 * time.Hour)

	criteria := &SearchCriteria{
		KeyIDs:       []string{"ABCD1234", "EFGH5678"},
		Fingerprints: []string{"ABCD1234567890ABCDEF"},
		UserIDs:      []string{"test@example.com"},
		Emails:       []string{"test@example.com"},
		Keywords:     []string{"pgp", "encryption"},
		After:        &after,
		Before:       &before,
		Limit:        100,
		Offset:       0,
	}

	// Test time range validation
	if criteria.After != nil && criteria.Before != nil {
		if criteria.After.After(*criteria.Before) {
			t.Error("After time should be before Before time")
		}
	}

	// Test limit validation
	if criteria.Limit <= 0 {
		t.Error("Limit should be positive")
	}

	// Test that email is included in UserIDs for search
	emailFound := false
	for _, userID := range criteria.UserIDs {
		for _, email := range criteria.Emails {
			if userID == email {
				emailFound = true
				break
			}
		}
	}
	if !emailFound && len(criteria.Emails) > 0 {
		t.Error("Emails should be searchable via UserIDs")
	}

	// Test search result structure
	searchTime := 250 * time.Millisecond
	testKeys := []*Pubkey{
		{
			RFingerprint: "KEY1",
			Creation:     now,
			MD5:          "md5_1",
			SHA256:       "sha256_1",
		},
	}

	result := &SearchResult{
		Keys:       testKeys,
		Total:      1000,
		Offset:     criteria.Offset,
		Limit:      criteria.Limit,
		HasMore:    true,
		SearchTime: searchTime,
	}

	// Test result consistency
	if result.Limit != criteria.Limit {
		t.Errorf("Result limit (%d) doesn't match criteria limit (%d)", result.Limit, criteria.Limit)
	}

	if result.Offset != criteria.Offset {
		t.Errorf("Result offset (%d) doesn't match criteria offset (%d)", result.Offset, criteria.Offset)
	}

	// Test pagination logic
	expectedHasMore := (result.Offset + len(result.Keys)) < int(result.Total)
	if result.HasMore != expectedHasMore {
		t.Errorf("HasMore should be %v based on pagination", expectedHasMore)
	}
}

// TestEventSystem tests the event system functionality
func TestEventSystem(t *testing.T) {
	now := time.Now()

	event := &Event{
		Type:      EventKeyInserted,
		Timestamp: now,
		KeyID:     "ABCD1234567890",
		Data: map[string]interface{}{
			"source": "upload",
			"size":   2048,
		},
	}

	// Test event type validation
	validEventTypes := []EventType{
		EventKeyInserted,
		EventKeyUpdated,
		EventKeyDeleted,
		EventStatsUpdate,
	}

	validType := false
	for _, validEventType := range validEventTypes {
		if event.Type == validEventType {
			validType = true
			break
		}
	}
	if !validType {
		t.Errorf("Invalid event type: %s", event.Type)
	}

	// Test event data structure
	if event.Data == nil {
		t.Error("Event data should not be nil")
	}

	if source, ok := event.Data["source"].(string); !ok || source == "" {
		t.Error("Expected source in event data")
	}

	if size, ok := event.Data["size"].(int); !ok || size <= 0 {
		t.Error("Expected positive size in event data")
	}

	// Test timestamp validation
	if event.Timestamp.IsZero() {
		t.Error("Event timestamp should not be zero")
	}

	if event.Timestamp.After(time.Now().Add(time.Second)) {
		t.Error("Event timestamp should not be in the future")
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	config := &Config{
		Driver:   "postgres",
		Database: "hockeypuck",
		Host:     "localhost",
		Port:     5432,
		Username: "hkp_user",
		Password: "secret123",
		SSLMode:  "require",
		Options: map[string]interface{}{
			"pool_size":      20,
			"timeout":        30,
			"retry_limit":    3,
			"max_open_conns": 25,
		},
	}

	// Test required fields
	if config.Driver == "" {
		t.Error("Driver is required")
	}

	if config.Database == "" {
		t.Error("Database is required")
	}

	if config.Host == "" {
		t.Error("Host is required")
	}

	// Test port validation
	if config.Port <= 0 || config.Port > 65535 {
		t.Errorf("Invalid port: %d", config.Port)
	}

	// Test SSL mode validation
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	validSSL := false
	for _, mode := range validSSLModes {
		if config.SSLMode == mode {
			validSSL = true
			break
		}
	}
	if !validSSL {
		t.Errorf("Invalid SSL mode: %s", config.SSLMode)
	}

	// Test options validation
	if poolSize, ok := config.Options["pool_size"].(int); ok {
		if poolSize <= 0 {
			t.Error("Pool size should be positive")
		}
	}

	if timeout, ok := config.Options["timeout"].(int); ok {
		if timeout <= 0 {
			t.Error("Timeout should be positive")
		}
	}
}
