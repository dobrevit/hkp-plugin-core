package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileCertificateStore implements CertificateStore using filesystem storage
type FileCertificateStore struct {
	storePath   string
	certs       map[string]*x509.Certificate
	metadata    map[string]*CertificateMetadata
	mutex       sync.RWMutex
	auditLogger SecurityAuditLogger
}

// CertificateMetadata contains additional certificate information
type CertificateMetadata struct {
	Fingerprint   string                 `json:"fingerprint"`
	AddedAt       time.Time              `json:"added_at"`
	AddedBy       string                 `json:"added_by"`
	TrustLevel    TrustLevel             `json:"trust_level"`
	Revoked       bool                   `json:"revoked"`
	RevokedAt     *time.Time             `json:"revoked_at,omitempty"`
	RevokedReason string                 `json:"revoked_reason,omitempty"`
	Attributes    map[string]interface{} `json:"attributes"`
}

// TrustLevel represents the level of trust for a certificate
type TrustLevel string

const (
	TrustLevelRoot         TrustLevel = "root"
	TrustLevelIntermediate TrustLevel = "intermediate"
	TrustLevelLeaf         TrustLevel = "leaf"
	TrustLevelUntrusted    TrustLevel = "untrusted"
)

// NewFileCertificateStore creates a new file-based certificate store
func NewFileCertificateStore(storePath string, auditLogger SecurityAuditLogger) (*FileCertificateStore, error) {
	store := &FileCertificateStore{
		storePath:   storePath,
		certs:       make(map[string]*x509.Certificate),
		metadata:    make(map[string]*CertificateMetadata),
		auditLogger: auditLogger,
	}

	// Create store directory if it doesn't exist
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	// Load existing certificates
	if err := store.loadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	return store, nil
}

// AddCertificate adds a certificate to the store
func (fs *FileCertificateStore) AddCertificate(cert *x509.Certificate) error {
	return fs.AddCertificateWithMetadata(cert, &CertificateMetadata{
		AddedAt:    time.Now(),
		AddedBy:    "system",
		TrustLevel: TrustLevelLeaf,
		Attributes: make(map[string]interface{}),
	})
}

// AddCertificateWithMetadata adds a certificate with specific metadata
func (fs *FileCertificateStore) AddCertificateWithMetadata(cert *x509.Certificate, metadata *CertificateMetadata) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	fingerprint := fs.calculateFingerprint(cert)
	metadata.Fingerprint = fingerprint

	// Check if certificate already exists
	if _, exists := fs.certs[fingerprint]; exists {
		return fmt.Errorf("certificate already exists: %s", fingerprint)
	}

	// Store certificate and metadata
	fs.certs[fingerprint] = cert
	fs.metadata[fingerprint] = metadata

	// Persist to disk
	if err := fs.saveCertificate(fingerprint, cert, metadata); err != nil {
		// Rollback in-memory changes
		delete(fs.certs, fingerprint)
		delete(fs.metadata, fingerprint)
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Log certificate addition
	certInfo := &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  fingerprint,
	}
	fs.auditLogger.LogCertificateOperation("add", certInfo)

	return nil
}

// RemoveCertificate removes a certificate from the store
func (fs *FileCertificateStore) RemoveCertificate(fingerprint string) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	cert, exists := fs.certs[fingerprint]
	if !exists {
		return fmt.Errorf("certificate not found: %s", fingerprint)
	}

	// Remove from memory
	delete(fs.certs, fingerprint)
	delete(fs.metadata, fingerprint)

	// Remove from disk
	certPath := fs.getCertificatePath(fingerprint)
	metadataPath := fs.getMetadataPath(fingerprint)

	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove certificate file: %w", err)
	}

	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove metadata file: %w", err)
	}

	// Log certificate removal
	certInfo := &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  fingerprint,
	}
	fs.auditLogger.LogCertificateOperation("remove", certInfo)

	return nil
}

// GetCertificate retrieves a certificate by fingerprint
func (fs *FileCertificateStore) GetCertificate(fingerprint string) (*x509.Certificate, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	cert, exists := fs.certs[fingerprint]
	if !exists {
		return nil, fmt.Errorf("certificate not found: %s", fingerprint)
	}

	return cert, nil
}

// ListCertificates returns all certificates in the store
func (fs *FileCertificateStore) ListCertificates() ([]*x509.Certificate, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	certs := make([]*x509.Certificate, 0, len(fs.certs))
	for _, cert := range fs.certs {
		certs = append(certs, cert)
	}

	return certs, nil
}

// GetCertificateMetadata retrieves metadata for a certificate
func (fs *FileCertificateStore) GetCertificateMetadata(fingerprint string) (*CertificateMetadata, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	metadata, exists := fs.metadata[fingerprint]
	if !exists {
		return nil, fmt.Errorf("certificate metadata not found: %s", fingerprint)
	}

	return metadata, nil
}

// RevokeCertificate marks a certificate as revoked
func (fs *FileCertificateStore) RevokeCertificate(fingerprint string, reason string) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	metadata, exists := fs.metadata[fingerprint]
	if !exists {
		return fmt.Errorf("certificate not found: %s", fingerprint)
	}

	cert := fs.certs[fingerprint]
	now := time.Now()

	metadata.Revoked = true
	metadata.RevokedAt = &now
	metadata.RevokedReason = reason

	// Save updated metadata
	if err := fs.saveMetadata(fingerprint, metadata); err != nil {
		return fmt.Errorf("failed to save revocation: %w", err)
	}

	// Log revocation
	certInfo := &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  fingerprint,
	}
	fs.auditLogger.LogCertificateOperation("revoke", certInfo)

	return nil
}

// VerifyChain verifies a certificate chain
func (fs *FileCertificateStore) VerifyChain(cert *x509.Certificate) error {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// Create certificate pool with trusted certificates
	pool := x509.NewCertPool()
	for _, trustedCert := range fs.certs {
		pool.AddCert(trustedCert)
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}

	_, err := cert.Verify(opts)
	return err
}

// Helper methods

// calculateFingerprint calculates SHA-256 fingerprint of a certificate
func (fs *FileCertificateStore) calculateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// getCertificatePath returns the file path for a certificate
func (fs *FileCertificateStore) getCertificatePath(fingerprint string) string {
	return filepath.Join(fs.storePath, fingerprint+".crt")
}

// getMetadataPath returns the file path for certificate metadata
func (fs *FileCertificateStore) getMetadataPath(fingerprint string) string {
	return filepath.Join(fs.storePath, fingerprint+".meta")
}

// saveCertificate saves a certificate and its metadata to disk
func (fs *FileCertificateStore) saveCertificate(fingerprint string, cert *x509.Certificate, metadata *CertificateMetadata) error {
	// Save certificate
	certPath := fs.getCertificatePath(fingerprint)
	if err := os.WriteFile(certPath, cert.Raw, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save metadata
	return fs.saveMetadata(fingerprint, metadata)
}

// saveMetadata saves certificate metadata to disk
func (fs *FileCertificateStore) saveMetadata(fingerprint string, metadata *CertificateMetadata) error {
	metadataPath := fs.getMetadataPath(fingerprint)
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// loadCertificates loads all certificates from disk
func (fs *FileCertificateStore) loadCertificates() error {
	pattern := filepath.Join(fs.storePath, "*.crt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob certificates: %w", err)
	}

	for _, certPath := range matches {
		if err := fs.loadCertificate(certPath); err != nil {
			// Log error but continue loading other certificates
			fs.auditLogger.LogSecurityEvent("certificate_load_error", map[string]interface{}{
				"path":  certPath,
				"error": err.Error(),
			})
		}
	}

	return nil
}

// loadCertificate loads a single certificate from disk
func (fs *FileCertificateStore) loadCertificate(certPath string) error {
	// Extract fingerprint from filename
	basename := filepath.Base(certPath)
	fingerprint := basename[:len(basename)-4] // Remove .crt extension

	// Load certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load metadata
	metadataPath := fs.getMetadataPath(fingerprint)
	var metadata *CertificateMetadata

	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		metadata = &CertificateMetadata{}
		if err := json.Unmarshal(metadataData, metadata); err != nil {
			return fmt.Errorf("failed to parse metadata: %w", err)
		}
	} else {
		// Create default metadata if file doesn't exist
		metadata = &CertificateMetadata{
			Fingerprint: fingerprint,
			AddedAt:     time.Now(),
			AddedBy:     "system",
			TrustLevel:  TrustLevelLeaf,
			Attributes:  make(map[string]interface{}),
		}
	}

	// Store in memory
	fs.certs[fingerprint] = cert
	fs.metadata[fingerprint] = metadata

	return nil
}
