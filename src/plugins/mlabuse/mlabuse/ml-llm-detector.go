package mlabuse

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// LLMPredictor detects LLM/AI-generated content and prompt injection attempts
type LLMPredictor struct {
	threshold        float64
	perplexityModel  *PerplexityAnalyzer
	tokenAnalyzer    *TokenPatternAnalyzer
	injectionScanner *PromptInjectionScanner
}

// PerplexityAnalyzer calculates text perplexity for AI detection
type PerplexityAnalyzer struct {
	ngramModel map[string]float64 // Simple n-gram frequency model
	vocabulary map[string]int
}

// TokenPatternAnalyzer detects AI-specific token patterns
type TokenPatternAnalyzer struct {
	aiPatterns      []string
	repetitionRatio float64
}

// PromptInjectionScanner detects prompt injection attempts
type PromptInjectionScanner struct {
	injectionPatterns []*regexp.Regexp
	suspiciousTerms   []string
}

// NewLLMPredictor creates a new LLM content predictor
func NewLLMPredictor(threshold float64) *LLMPredictor {
	return &LLMPredictor{
		threshold:        threshold,
		perplexityModel:  newPerplexityAnalyzer(),
		tokenAnalyzer:    newTokenPatternAnalyzer(),
		injectionScanner: newPromptInjectionScanner(),
	}
}

// newPerplexityAnalyzer creates a perplexity analyzer with pre-trained data
func newPerplexityAnalyzer() *PerplexityAnalyzer {
	return &PerplexityAnalyzer{
		ngramModel: initializeNgramModel(),
		vocabulary: initializeVocabulary(),
	}
}

// newTokenPatternAnalyzer creates a token pattern analyzer
func newTokenPatternAnalyzer() *TokenPatternAnalyzer {
	return &TokenPatternAnalyzer{
		aiPatterns: []string{
			// Common AI-generated patterns
			"As an AI", "I understand", "However,", "Additionally,",
			"Furthermore,", "In conclusion,", "It's important to note",
			"I must", "I cannot", "I'm unable to", "ethical",
			"It's worth noting", "To summarize", "In summary",
		},
		repetitionRatio: 0.3,
	}
}

// newPromptInjectionScanner creates a prompt injection scanner
func newPromptInjectionScanner() *PromptInjectionScanner {
	patterns := []string{
		`(?i)ignore\s+previous\s+instructions`,
		`(?i)disregard\s+all\s+prior`,
		`(?i)new\s+instructions:`,
		`(?i)system\s*:`,
		`(?i)admin\s*:`,
		`(?i)<\|.*\|>`, // Special tokens
		`(?i)###\s*instruction`,
		`(?i)""".*"""`, // Triple quotes
		`(?i)''.*''`,   // Triple single quotes
		`(?i)role\s*:\s*system`,
		`(?i)</s>`, // End tokens
		`\x00`,     // Null bytes
	}

	compiledPatterns := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		compiledPatterns[i] = regexp.MustCompile(pattern)
	}

	return &PromptInjectionScanner{
		injectionPatterns: compiledPatterns,
		suspiciousTerms: []string{
			"jailbreak", "DAN", "bypass", "override",
			"sudo", "admin", "root", "system prompt",
			"ignore safety", "new persona", "act as",
		},
	}
}

// DetectLLMContent analyzes HTTP request for AI-generated content
func (p *LLMPredictor) DetectLLMContent(r *http.Request) *LLMDetectionResult {
	result := &LLMDetectionResult{
		TokenPatterns: make([]string, 0),
	}

	// Read request body
	body, err := p.readRequestBody(r)
	if err != nil || len(body) == 0 {
		return result
	}

	// Analyze text content
	text := string(body)

	// Calculate perplexity
	result.Perplexity = p.perplexityModel.calculatePerplexity(text)

	// Detect token patterns
	patterns, score := p.tokenAnalyzer.analyzePatterns(text)
	result.TokenPatterns = patterns

	// Check for prompt injection
	result.PromptInjection = p.injectionScanner.detectInjection(text)

	// Calculate synthetic score
	result.SyntheticScore = p.calculateSyntheticScore(result.Perplexity, score, len(patterns))

	// Determine if AI-generated
	result.IsAIGenerated = result.SyntheticScore >= p.threshold || result.PromptInjection

	return result
}

// AnalyzeText analyzes the provided text for LLM/AI-generated content
func (p *LLMPredictor) AnalyzeText(text string) *LLMDetectionResult {
	result := &LLMDetectionResult{
		TokenPatterns: make([]string, 0),
	}

	// Skip empty text
	if len(strings.TrimSpace(text)) == 0 {
		return result
	}

	// Calculate perplexity
	result.Perplexity = p.perplexityModel.calculatePerplexity(text)

	// Detect token patterns
	patterns, score := p.tokenAnalyzer.analyzePatterns(text)
	result.TokenPatterns = patterns

	// Check for prompt injection
	result.PromptInjection = p.injectionScanner.detectInjection(text)

	// Calculate synthetic score
	result.SyntheticScore = p.calculateSyntheticScore(result.Perplexity, score, len(patterns))

	// Determine if AI-generated
	result.IsAIGenerated = result.SyntheticScore >= p.threshold || result.PromptInjection

	return result
}

// readRequestBody safely reads and restores request body
func (p *LLMPredictor) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// calculatePerplexity calculates text perplexity using n-gram model
func (pa *PerplexityAnalyzer) calculatePerplexity(text string) float64 {
	// Tokenize text
	tokens := pa.tokenize(text)
	if len(tokens) < 2 {
		return 1.0 // Low perplexity for very short text
	}

	// Calculate log probability
	logProb := 0.0
	count := 0

	// Bigram perplexity
	for i := 1; i < len(tokens); i++ {
		bigram := tokens[i-1] + " " + tokens[i]
		prob, exists := pa.ngramModel[bigram]
		if !exists {
			prob = 1e-10 // Smoothing for unseen bigrams
		}
		logProb += math.Log(prob)
		count++
	}

	// Calculate perplexity
	if count == 0 {
		return 1.0
	}

	avgLogProb := logProb / float64(count)
	perplexity := math.Exp(-avgLogProb)

	// Normalize to 0-1 range (lower perplexity = more AI-like)
	normalized := 1.0 / (1.0 + perplexity/100.0)

	return normalized
}

// tokenize splits text into tokens
func (pa *PerplexityAnalyzer) tokenize(text string) []string {
	// Simple tokenization - in production, use proper NLP tokenizer
	text = strings.ToLower(text)

	// Split by whitespace and punctuation
	var tokens []string
	var currentToken strings.Builder

	for _, ch := range text {
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			currentToken.WriteRune(ch)
		} else {
			if currentToken.Len() > 0 {
				tokens = append(tokens, currentToken.String())
				currentToken.Reset()
			}
		}
	}

	if currentToken.Len() > 0 {
		tokens = append(tokens, currentToken.String())
	}

	return tokens
}

// analyzePatterns detects AI-specific patterns in text
func (ta *TokenPatternAnalyzer) analyzePatterns(text string) ([]string, float64) {
	foundPatterns := make([]string, 0)
	score := 0.0

	// Check for AI patterns
	for _, pattern := range ta.aiPatterns {
		if strings.Contains(text, pattern) {
			foundPatterns = append(foundPatterns, pattern)
			score += 0.1
		}
	}

	// Check for repetitive structure
	sentences := strings.Split(text, ".")
	if len(sentences) > 3 {
		// Check sentence beginnings
		beginnings := make(map[string]int)
		for _, sentence := range sentences {
			trimmed := strings.TrimSpace(sentence)
			if len(trimmed) > 5 {
				beginning := strings.Split(trimmed, " ")[0]
				beginnings[beginning]++
			}
		}

		// High repetition of sentence starters
		for _, count := range beginnings {
			if float64(count)/float64(len(sentences)) > ta.repetitionRatio {
				score += 0.2
				foundPatterns = append(foundPatterns, "repetitive_structure")
				break
			}
		}
	}

	// Check for overly formal language
	formalIndicators := []string{
		"therefore", "hence", "thus", "moreover",
		"nevertheless", "consequently", "furthermore",
	}

	formalCount := 0
	for _, indicator := range formalIndicators {
		formalCount += strings.Count(strings.ToLower(text), indicator)
	}

	if float64(formalCount)/float64(len(strings.Fields(text))) > 0.02 {
		score += 0.15
		foundPatterns = append(foundPatterns, "formal_language")
	}

	// Cap score at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return foundPatterns, score
}

// detectInjection checks for prompt injection attempts
func (pis *PromptInjectionScanner) detectInjection(text string) bool {
	// Check regex patterns
	for _, pattern := range pis.injectionPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}

	// Check suspicious terms
	lowerText := strings.ToLower(text)
	for _, term := range pis.suspiciousTerms {
		if strings.Contains(lowerText, term) {
			return true
		}
	}

	// Check for unusual character sequences
	if strings.Contains(text, "\\x") || strings.Contains(text, "\\u") {
		return true
	}

	// Check for base64 encoded content (common in injections)
	if b64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`); b64Pattern.MatchString(text) {
		// Additional check for base64 patterns that might hide injections
		return true
	}

	return false
}

// calculateSyntheticScore combines multiple signals into a single score
func (p *LLMPredictor) calculateSyntheticScore(perplexity float64, patternScore float64, patternCount int) float64 {
	// Weight different components
	perplexityWeight := 0.4
	patternWeight := 0.4
	countWeight := 0.2

	// Normalize pattern count (0-1 range)
	normalizedCount := math.Min(float64(patternCount)/10.0, 1.0)

	// Calculate weighted score
	score := perplexity*perplexityWeight +
		patternScore*patternWeight +
		normalizedCount*countWeight

	// Apply non-linear transformation for better discrimination
	// This makes the score more sensitive to multiple indicators
	score = math.Pow(score, 0.8)

	return score
}

// initializeNgramModel creates a simple n-gram frequency model
func initializeNgramModel() map[string]float64 {
	// In production, this would be loaded from a trained model
	// For now, we'll use representative frequencies
	model := map[string]float64{
		// Common human bigrams
		"the key":    0.02,
		"key server": 0.015,
		"public key": 0.018,
		"i want":     0.01,
		"can you":    0.008,
		"need to":    0.009,
		"trying to":  0.007,
		"my key":     0.012,
		"gpg key":    0.01,
		"ssh key":    0.008,

		// Less common/AI-like bigrams
		"as an":         0.001,
		"it is":         0.003,
		"however the":   0.0008,
		"furthermore i": 0.0005,
		"in conclusion": 0.0004,
		"to summarize":  0.0003,
		"i must":        0.0006,
		"i cannot":      0.0007,
		"important to":  0.002,
		"worth noting":  0.0009,
	}

	// Add more patterns programmatically
	commonWords := []string{"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for"}
	for _, w1 := range commonWords {
		for _, w2 := range commonWords {
			bigram := w1 + " " + w2
			if _, exists := model[bigram]; !exists {
				model[bigram] = 0.005 // Default frequency
			}
		}
	}

	return model
}

// initializeVocabulary creates a vocabulary frequency map
func initializeVocabulary() map[string]int {
	// Common words in key server context
	vocab := map[string]int{
		"key":         100,
		"public":      80,
		"private":     70,
		"gpg":         90,
		"pgp":         85,
		"ssh":         75,
		"server":      95,
		"upload":      60,
		"download":    65,
		"search":      70,
		"find":        68,
		"user":        85,
		"email":       88,
		"fingerprint": 72,
		"signature":   76,
		"verify":      62,
		"trust":       58,
		"revoke":      45,
		"expire":      48,
		"generate":    52,
	}

	return vocab
}
