// Package storage provides storage interfaces for Hockeypuck
package storage

import (
	"context"
	"io"
	"time"
)

// Storage represents the main storage interface for OpenPGP keys
type Storage interface {
	// Key operations
	MatchMD5([]string) ([]string, error)
	ModifiedSince(time.Time) ([]string, error)
	FetchKeys([]string) ([]*Pubkey, error)
	FetchKeysPrefix(string) ([]*Pubkey, error)
	Insert([]*Pubkey) error
	Update(*Pubkey, *Pubkey) error
	Delete([]string) error

	// Statistics
	Stats() (*Stats, error)

	// Health check
	Healthy() error

	// Recon operations
	ReconStats() (*ReconStats, error)
	ReconState() (ReconState, error)

	// Close
	Close() error
}

// Pubkey represents an OpenPGP public key
type Pubkey struct {
	RFingerprint string     `json:"rfingerprint"`
	Creation     time.Time  `json:"creation"`
	Expiration   *time.Time `json:"expiration,omitempty"`
	State        int        `json:"state"`
	Packet       []byte     `json:"packet"`
	Ctime        time.Time  `json:"ctime"`
	Mtime        time.Time  `json:"mtime"`
	MD5          string     `json:"md5"`
	SHA256       string     `json:"sha256"`
	Size         int        `json:"size"`

	// Associated data
	Identities []*Identity  `json:"identities,omitempty"`
	SubKeys    []*SubKey    `json:"subkeys,omitempty"`
	Signatures []*Signature `json:"signatures,omitempty"`
}

// Identity represents a user identity
type Identity struct {
	ScopedDigest string     `json:"scoped_digest"`
	Packet       []byte     `json:"packet"`
	Creation     time.Time  `json:"creation"`
	Expiration   *time.Time `json:"expiration,omitempty"`
	State        int        `json:"state"`
	Ctime        time.Time  `json:"ctime"`
	Mtime        time.Time  `json:"mtime"`
	Keywords     []string   `json:"keywords,omitempty"`
}

// SubKey represents a subkey
type SubKey struct {
	RFingerprint string     `json:"rfingerprint"`
	Creation     time.Time  `json:"creation"`
	Expiration   *time.Time `json:"expiration,omitempty"`
	State        int        `json:"state"`
	Packet       []byte     `json:"packet"`
	Ctime        time.Time  `json:"ctime"`
	Mtime        time.Time  `json:"mtime"`
}

// Signature represents a signature
type Signature struct {
	ScopedDigest string     `json:"scoped_digest"`
	Packet       []byte     `json:"packet"`
	Creation     time.Time  `json:"creation"`
	Expiration   *time.Time `json:"expiration,omitempty"`
	State        int        `json:"state"`
	Ctime        time.Time  `json:"ctime"`
	Mtime        time.Time  `json:"mtime"`
}

// Stats represents storage statistics
type Stats struct {
	Total      int64     `json:"total"`
	Inserted   int64     `json:"inserted"`
	Updated    int64     `json:"updated"`
	Ignored    int64     `json:"ignored"`
	Duplicates int64     `json:"duplicates"`
	LastUpdate time.Time `json:"last_update"`
}

// ReconStats represents recon statistics
type ReconStats struct {
	Total       int64     `json:"total"`
	LastUpdate  time.Time `json:"last_update"`
	SyncStarted time.Time `json:"sync_started,omitempty"`
	SyncStatus  string    `json:"sync_status"`
}

// ReconState represents the recon state
type ReconState struct {
	Version   int                    `json:"version"`
	HTTPAddr  string                 `json:"http_addr"`
	ReconAddr string                 `json:"recon_addr"`
	Filters   []string               `json:"filters"`
	Stats     *ReconStats            `json:"stats"`
	Settings  map[string]interface{} `json:"settings"`
}

// KeyReader provides streaming access to keys
type KeyReader interface {
	io.Reader
	Next() (*Pubkey, error)
	Close() error
}

// KeyWriter provides streaming writing of keys
type KeyWriter interface {
	io.Writer
	WriteKey(*Pubkey) error
	Close() error
}

// SearchCriteria represents search criteria for keys
type SearchCriteria struct {
	KeyIDs       []string   `json:"key_ids,omitempty"`
	Fingerprints []string   `json:"fingerprints,omitempty"`
	UserIDs      []string   `json:"user_ids,omitempty"`
	Emails       []string   `json:"emails,omitempty"`
	Keywords     []string   `json:"keywords,omitempty"`
	After        *time.Time `json:"after,omitempty"`
	Before       *time.Time `json:"before,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}

// SearchResult represents search results
type SearchResult struct {
	Keys       []*Pubkey     `json:"keys"`
	Total      int64         `json:"total"`
	Offset     int           `json:"offset"`
	Limit      int           `json:"limit"`
	HasMore    bool          `json:"has_more"`
	SearchTime time.Duration `json:"search_time"`
}

// Transaction represents a storage transaction
type Transaction interface {
	// Key operations within transaction
	Insert([]*Pubkey) error
	Update(*Pubkey, *Pubkey) error
	Delete([]string) error

	// Transaction control
	Commit() error
	Rollback() error
}

// TransactionalStorage extends Storage with transaction support
type TransactionalStorage interface {
	Storage
	Begin() (Transaction, error)
}

// Config represents storage configuration
type Config struct {
	Driver   string                 `toml:"driver"`
	Database string                 `toml:"database"`
	Host     string                 `toml:"host"`
	Port     int                    `toml:"port"`
	Username string                 `toml:"username"`
	Password string                 `toml:"password"`
	SSLMode  string                 `toml:"sslmode"`
	Options  map[string]interface{} `toml:"options"`
}

// Factory creates storage instances
type Factory interface {
	Create(config Config) (Storage, error)
	DriverName() string
	ConfigSchema() map[string]interface{}
}

// Event represents a storage event
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	KeyID     string                 `json:"key_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// EventType represents the type of storage event
type EventType string

const (
	EventKeyInserted EventType = "key_inserted"
	EventKeyUpdated  EventType = "key_updated"
	EventKeyDeleted  EventType = "key_deleted"
	EventStatsUpdate EventType = "stats_update"
)

// EventHandler handles storage events
type EventHandler func(Event) error

// EventfulStorage extends Storage with event support
type EventfulStorage interface {
	Storage
	Subscribe(EventType, EventHandler) error
	Unsubscribe(EventType, EventHandler) error
	PublishEvent(Event) error
}

// HealthChecker provides health checking capabilities
type HealthChecker interface {
	HealthCheck(ctx context.Context) error
	HealthStatus() HealthStatus
}

// HealthStatus represents health status
type HealthStatus struct {
	Healthy      bool                   `json:"healthy"`
	LastCheck    time.Time              `json:"last_check"`
	Details      map[string]interface{} `json:"details,omitempty"`
	Errors       []string               `json:"errors,omitempty"`
	ResponseTime time.Duration          `json:"response_time"`
}

// MetricsCollector provides metrics collection
type MetricsCollector interface {
	CollectMetrics() (map[string]interface{}, error)
	RegisterMetric(name string, collector func() interface{}) error
}

// BackupStorage provides backup capabilities
type BackupStorage interface {
	Backup(ctx context.Context, destination string) error
	Restore(ctx context.Context, source string) error
	ListBackups() ([]BackupInfo, error)
}

// BackupInfo represents backup information
type BackupInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Created    time.Time `json:"created"`
	Size       int64     `json:"size"`
	Compressed bool      `json:"compressed"`
	Checksum   string    `json:"checksum"`
	KeyCount   int64     `json:"key_count"`
}

// CacheStorage provides caching capabilities
type CacheStorage interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
	Clear() error
	Stats() CacheStats
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	Entries     int64   `json:"entries"`
	Size        int64   `json:"size"`
	Evictions   int64   `json:"evictions"`
	HitRate     float64 `json:"hit_rate"`
	MemoryUsage int64   `json:"memory_usage"`
}

// ReplicationStorage provides replication capabilities
type ReplicationStorage interface {
	Storage
	StartReplication(peers []ReplicationPeer) error
	StopReplication() error
	ReplicationStatus() ReplicationStatus
}

// ReplicationPeer represents a replication peer
type ReplicationPeer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Priority int    `json:"priority"`
	ReadOnly bool   `json:"read_only"`
}

// ReplicationStatus represents replication status
type ReplicationStatus struct {
	Active     bool                    `json:"active"`
	Peers      []ReplicationPeerStatus `json:"peers"`
	LastSync   time.Time               `json:"last_sync"`
	SyncErrors []ReplicationError      `json:"sync_errors,omitempty"`
	Stats      map[string]interface{}  `json:"stats"`
}

// ReplicationPeerStatus represents peer status
type ReplicationPeerStatus struct {
	ID         string        `json:"id"`
	Address    string        `json:"address"`
	Connected  bool          `json:"connected"`
	LastSync   time.Time     `json:"last_sync"`
	Lag        time.Duration `json:"lag"`
	ErrorCount int           `json:"error_count"`
	LastError  string        `json:"last_error,omitempty"`
}

// ReplicationError represents a replication error
type ReplicationError struct {
	Timestamp time.Time `json:"timestamp"`
	PeerID    string    `json:"peer_id"`
	Error     string    `json:"error"`
	KeyID     string    `json:"key_id,omitempty"`
}

// IndexStorage provides indexing capabilities
type IndexStorage interface {
	CreateIndex(name string, fields []string) error
	DropIndex(name string) error
	ListIndexes() ([]IndexInfo, error)
	ReindexAll() error
}

// IndexInfo represents index information
type IndexInfo struct {
	Name     string    `json:"name"`
	Fields   []string  `json:"fields"`
	Unique   bool      `json:"unique"`
	Created  time.Time `json:"created"`
	Size     int64     `json:"size"`
	KeyCount int64     `json:"key_count"`
}

// CompressionStorage provides compression capabilities
type CompressionStorage interface {
	SetCompressionLevel(level int) error
	GetCompressionLevel() int
	CompressedSize() (int64, error)
	UncompressedSize() (int64, error)
	CompressionRatio() (float64, error)
}

// PartitionedStorage provides partitioning capabilities
type PartitionedStorage interface {
	Storage
	CreatePartition(name string, criteria PartitionCriteria) error
	DropPartition(name string) error
	ListPartitions() ([]PartitionInfo, error)
	GetPartition(keyID string) (string, error)
}

// PartitionCriteria represents partitioning criteria
type PartitionCriteria struct {
	Type        PartitionType          `json:"type"`
	Field       string                 `json:"field"`
	Values      []interface{}          `json:"values,omitempty"`
	Ranges      []PartitionRange       `json:"ranges,omitempty"`
	HashBuckets int                    `json:"hash_buckets,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// PartitionType represents the type of partitioning
type PartitionType string

const (
	PartitionByRange PartitionType = "range"
	PartitionByList  PartitionType = "list"
	PartitionByHash  PartitionType = "hash"
	PartitionByDate  PartitionType = "date"
)

// PartitionRange represents a partition range
type PartitionRange struct {
	Start interface{} `json:"start"`
	End   interface{} `json:"end"`
	Name  string      `json:"name"`
}

// PartitionInfo represents partition information
type PartitionInfo struct {
	Name      string            `json:"name"`
	Criteria  PartitionCriteria `json:"criteria"`
	KeyCount  int64             `json:"key_count"`
	Size      int64             `json:"size"`
	Created   time.Time         `json:"created"`
	LastWrite time.Time         `json:"last_write"`
}

// StreamingStorage provides streaming capabilities
type StreamingStorage interface {
	StreamKeys(criteria SearchCriteria) (KeyReader, error)
	ImportKeys(reader KeyReader) error
	ExportKeys(criteria SearchCriteria, writer KeyWriter) error
}

// ConcurrentStorage provides safe concurrent access
type ConcurrentStorage interface {
	Storage
	ReadLock() error
	ReadUnlock() error
	WriteLock() error
	WriteUnlock() error
	TryReadLock() bool
	TryWriteLock() bool
}

// VersionedStorage provides versioning capabilities
type VersionedStorage interface {
	Storage
	GetVersion() int64
	ListVersions() ([]VersionInfo, error)
	GetKeyVersion(keyID string, version int64) (*Pubkey, error)
	GetKeyHistory(keyID string) ([]VersionInfo, error)
}

// VersionInfo represents version information
type VersionInfo struct {
	Version   int64     `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	KeyID     string    `json:"key_id,omitempty"`
	Operation string    `json:"operation"`
	Size      int64     `json:"size"`
	Checksum  string    `json:"checksum"`
}

// ReadOnlyStorage provides read-only access
type ReadOnlyStorage interface {
	// Read operations only
	MatchMD5([]string) ([]string, error)
	ModifiedSince(time.Time) ([]string, error)
	FetchKeys([]string) ([]*Pubkey, error)
	FetchKeysPrefix(string) ([]*Pubkey, error)
	Stats() (*Stats, error)
	Healthy() error
	ReconStats() (*ReconStats, error)
	ReconState() (ReconState, error)
	Close() error
}

// WriteOnlyStorage provides write-only access
type WriteOnlyStorage interface {
	// Write operations only
	Insert([]*Pubkey) error
	Update(*Pubkey, *Pubkey) error
	Delete([]string) error
	Close() error
}

// Default implementations and utilities

// NoOpStorage provides a no-operation storage implementation
type NoOpStorage struct{}

func (n *NoOpStorage) MatchMD5([]string) ([]string, error)       { return nil, nil }
func (n *NoOpStorage) ModifiedSince(time.Time) ([]string, error) { return nil, nil }
func (n *NoOpStorage) FetchKeys([]string) ([]*Pubkey, error)     { return nil, nil }
func (n *NoOpStorage) FetchKeysPrefix(string) ([]*Pubkey, error) { return nil, nil }
func (n *NoOpStorage) Insert([]*Pubkey) error                    { return nil }
func (n *NoOpStorage) Update(*Pubkey, *Pubkey) error             { return nil }
func (n *NoOpStorage) Delete([]string) error                     { return nil }
func (n *NoOpStorage) Stats() (*Stats, error)                    { return &Stats{}, nil }
func (n *NoOpStorage) Healthy() error                            { return nil }
func (n *NoOpStorage) ReconStats() (*ReconStats, error)          { return &ReconStats{}, nil }
func (n *NoOpStorage) ReconState() (ReconState, error)           { return ReconState{}, nil }
func (n *NoOpStorage) Close() error                              { return nil }
