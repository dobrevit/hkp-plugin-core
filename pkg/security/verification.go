// Package security provides plugin verification and security management
package security

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// PluginVerifier handles plugin signature verification and trust management
type PluginVerifier struct {
	trustedCerts    map[string]*x509.Certificate
	verificationAlg SignatureAlgorithm
	cacheManager    *VerificationCache
	certStore       CertificateStore
	auditLogger     SecurityAuditLogger
	mutex           sync.RWMutex
}

// SignatureAlgorithm represents supported signature algorithms
type SignatureAlgorithm string

const (
	AlgorithmRSA4096 SignatureAlgorithm = "RSA-4096"
	AlgorithmEd25519 SignatureAlgorithm = "Ed25519"
	AlgorithmECDSA   SignatureAlgorithm = "ECDSA-P256"
)

// VerificationResult contains the result of plugin verification
type VerificationResult struct {
	Valid            bool               `json:"valid"`
	Algorithm        SignatureAlgorithm `json:"algorithm"`
	Certificate      *CertificateInfo   `json:"certificate"`
	Timestamp        time.Time          `json:"timestamp"`
	Error            string             `json:"error,omitempty"`
	TrustChain       []*CertificateInfo `json:"trust_chain"`
	RevocationStatus RevocationStatus   `json:"revocation_status"`
}

// CertificateInfo contains certificate metadata
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Fingerprint  string    `json:"fingerprint"`
	KeyUsage     []string  `json:"key_usage"`
}

// RevocationStatus indicates certificate revocation status
type RevocationStatus string

const (
	RevocationStatusValid   RevocationStatus = "valid"
	RevocationStatusRevoked RevocationStatus = "revoked"
	RevocationStatusUnknown RevocationStatus = "unknown"
)

// CertificateStore manages trusted certificates
type CertificateStore interface {
	AddCertificate(cert *x509.Certificate) error
	RemoveCertificate(fingerprint string) error
	GetCertificate(fingerprint string) (*x509.Certificate, error)
	ListCertificates() ([]*x509.Certificate, error)
	VerifyChain(cert *x509.Certificate) error
}

// SecurityAuditLogger logs security events
type SecurityAuditLogger interface {
	LogVerification(pluginPath string, result *VerificationResult)
	LogCertificateOperation(operation string, cert *CertificateInfo)
	LogSecurityEvent(event string, details map[string]interface{})
	LogPluginSecurityViolation(pluginName string, violation string, details map[string]interface{})
	LogResourceViolation(pluginName string, resource string, limit interface{}, actual interface{})
	LogFailureRecovery(pluginName string, failureType string, recoveryAction string, success bool)
}

// VerificationCache caches verification results
type VerificationCache struct {
	cache  map[string]*CacheEntry
	mutex  sync.RWMutex
	maxAge time.Duration
}

// CacheEntry represents a cached verification result
type CacheEntry struct {
	Result    *VerificationResult
	Timestamp time.Time
	Hash      string
}

// NewPluginVerifier creates a new plugin verifier instance
func NewPluginVerifier(certStore CertificateStore, auditLogger SecurityAuditLogger) *PluginVerifier {
	return &PluginVerifier{
		trustedCerts:    make(map[string]*x509.Certificate),
		verificationAlg: AlgorithmEd25519,                // Default to Ed25519
		cacheManager:    NewVerificationCache(time.Hour), // 1 hour cache
		certStore:       certStore,
		auditLogger:     auditLogger,
	}
}

// NewVerificationCache creates a new verification cache
func NewVerificationCache(maxAge time.Duration) *VerificationCache {
	return &VerificationCache{
		cache:  make(map[string]*CacheEntry),
		maxAge: maxAge,
	}
}

// VerifyPlugin verifies a plugin's signature and integrity
func (pv *PluginVerifier) VerifyPlugin(pluginPath string) (*VerificationResult, error) {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()
	result := &VerificationResult{
		Timestamp: time.Now(),
	}

	// Check if plugin file exists
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		result.Valid = false
		result.Error = "plugin file not found"
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Calculate plugin hash for cache lookup
	pluginHash, err := pv.calculatePluginHash(pluginPath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to calculate plugin hash: %v", err)
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Check cache first
	if cached := pv.cacheManager.Get(pluginHash); cached != nil {
		pv.auditLogger.LogVerification(pluginPath, cached.Result)
		return cached.Result, nil
	}

	// Look for signature file
	signaturePath := pluginPath + ".sig"
	if _, err := os.Stat(signaturePath); os.IsNotExist(err) {
		result.Valid = false
		result.Error = "signature file not found"
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Read and verify signature
	signature, cert, err := pv.readSignature(signaturePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to read signature: %v", err)
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Verify certificate chain
	if err := pv.certStore.VerifyChain(cert); err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("certificate chain verification failed: %v", err)
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Check certificate revocation status
	revocationStatus := pv.checkRevocationStatus(cert)
	result.RevocationStatus = revocationStatus

	if revocationStatus == RevocationStatusRevoked {
		result.Valid = false
		result.Error = "certificate has been revoked"
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Verify plugin signature
	valid, err := pv.verifySignature(pluginPath, signature, cert)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("signature verification failed: %v", err)
		pv.auditLogger.LogVerification(pluginPath, result)
		return result, nil
	}

	// Build result
	result.Valid = valid
	result.Algorithm = pv.detectAlgorithm(cert.PublicKey)
	result.Certificate = pv.buildCertificateInfo(cert)
	result.TrustChain = pv.buildTrustChain(cert)

	// Cache the result
	pv.cacheManager.Set(pluginHash, result)

	// Log verification
	pv.auditLogger.LogVerification(pluginPath, result)

	return result, nil
}

// calculatePluginHash calculates SHA-256 hash of the plugin file
func (pv *PluginVerifier) calculatePluginHash(pluginPath string) (string, error) {
	file, err := os.Open(pluginPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// readSignature reads and parses the signature file
func (pv *PluginVerifier) readSignature(signaturePath string) ([]byte, *x509.Certificate, error) {
	data, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, nil, err
	}

	// Parse PEM blocks
	var signature []byte
	var cert *x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "SIGNATURE":
			signature = block.Bytes
		case "CERTIFICATE":
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
		}

		data = rest
	}

	if signature == nil {
		return nil, nil, fmt.Errorf("signature not found in file")
	}
	if cert == nil {
		return nil, nil, fmt.Errorf("certificate not found in file")
	}

	return signature, cert, nil
}

// verifySignature verifies the plugin signature using the certificate
func (pv *PluginVerifier) verifySignature(pluginPath string, signature []byte, cert *x509.Certificate) (bool, error) {
	// Read plugin file
	pluginData, err := os.ReadFile(pluginPath)
	if err != nil {
		return false, err
	}

	// Calculate hash
	hash := sha256.Sum256(pluginData)

	// Verify based on key type
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
		return err == nil, err

	case ed25519.PublicKey:
		return ed25519.Verify(pub, hash[:], signature), nil

	default:
		return false, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// detectAlgorithm detects the signature algorithm from the public key
func (pv *PluginVerifier) detectAlgorithm(publicKey crypto.PublicKey) SignatureAlgorithm {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key.Size() >= 512 { // 4096 bits
			return AlgorithmRSA4096
		}
		return SignatureAlgorithm("RSA-" + fmt.Sprintf("%d", key.Size()*8))
	case ed25519.PublicKey:
		return AlgorithmEd25519
	default:
		return SignatureAlgorithm("UNKNOWN")
	}
}

// buildCertificateInfo extracts certificate information
func (pv *PluginVerifier) buildCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "digital_signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "key_encipherment")
	}
	// Check for code signing in extended key usage
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			keyUsage = append(keyUsage, "code_signing")
			break
		}
	}

	return &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  fingerprint,
		KeyUsage:     keyUsage,
	}
}

// buildTrustChain builds the certificate trust chain
func (pv *PluginVerifier) buildTrustChain(cert *x509.Certificate) []*CertificateInfo {
	chain := []*CertificateInfo{pv.buildCertificateInfo(cert)}

	// For now, return just the leaf certificate
	// In a full implementation, this would walk the entire chain
	return chain
}

// checkRevocationStatus checks if a certificate has been revoked
func (pv *PluginVerifier) checkRevocationStatus(cert *x509.Certificate) RevocationStatus {
	// TODO: Implement OCSP/CRL checking
	// For now, assume valid if not expired
	if time.Now().After(cert.NotAfter) {
		return RevocationStatusRevoked
	}
	return RevocationStatusValid
}

// Cache methods

// Get retrieves a cached verification result
func (vc *VerificationCache) Get(hash string) *CacheEntry {
	vc.mutex.RLock()
	defer vc.mutex.RUnlock()

	entry, exists := vc.cache[hash]
	if !exists {
		return nil
	}

	// Check if entry is expired
	if time.Since(entry.Timestamp) > vc.maxAge {
		delete(vc.cache, hash)
		return nil
	}

	return entry
}

// Set stores a verification result in cache
func (vc *VerificationCache) Set(hash string, result *VerificationResult) {
	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	vc.cache[hash] = &CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
		Hash:      hash,
	}
}

// Clear removes expired entries from cache
func (vc *VerificationCache) Clear() {
	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	now := time.Now()
	for hash, entry := range vc.cache {
		if now.Sub(entry.Timestamp) > vc.maxAge {
			delete(vc.cache, hash)
		}
	}
}
