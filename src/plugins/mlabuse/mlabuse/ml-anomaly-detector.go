package mlabuse

import (
	"encoding/gob"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"
)

// AnomalyDetector implements Isolation Forest algorithm for anomaly detection
type AnomalyDetector struct {
	modelPath string
	threshold float64
	forest    *IsolationForest
	mu        sync.RWMutex
}

// IsolationForest represents the ensemble of isolation trees
type IsolationForest struct {
	Trees         []*IsolationTree
	NumTrees      int
	SampleSize    int
	MaxDepth      int
	FeatureNames  []string
	AnomalyScores map[string]float64 // Cache for recent scores
}

// IsolationTree represents a single tree in the forest
type IsolationTree struct {
	Root       *IsolationNode
	PathLength map[string]float64
}

// IsolationNode represents a node in the isolation tree
type IsolationNode struct {
	IsLeaf       bool
	SplitFeature int
	SplitValue   float64
	Left         *IsolationNode
	Right        *IsolationNode
	Size         int // Number of samples at this node
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(modelPath string, threshold float64) *AnomalyDetector {
	return &AnomalyDetector{
		modelPath: modelPath,
		threshold: threshold,
		forest: &IsolationForest{
			NumTrees:      100,
			SampleSize:    256,
			MaxDepth:      10,
			AnomalyScores: make(map[string]float64),
			FeatureNames: []string{
				"avg_interval", "interval_variance", "timing_entropy",
				"path_entropy", "overall_entropy", "request_count",
				"unique_paths", "error_rate", "key_op_ratio",
				"user_agents", "payload_similarity",
			},
		},
	}
}

// LoadModel loads the trained model from disk
func (ad *AnomalyDetector) LoadModel() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Check if model file exists
	if _, err := os.Stat(ad.modelPath); os.IsNotExist(err) {
		// Initialize with default model if file doesn't exist
		return ad.initializeDefaultModel()
	}

	// Load model from file
	file, err := os.Open(ad.modelPath)
	if err != nil {
		return fmt.Errorf("failed to open model file: %w", err)
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&ad.forest); err != nil {
		return fmt.Errorf("failed to decode model: %w", err)
	}

	return nil
}

// SaveModel saves the current model to disk
func (ad *AnomalyDetector) SaveModel() error {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	file, err := os.Create(ad.modelPath)
	if err != nil {
		return fmt.Errorf("failed to create model file: %w", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(ad.forest); err != nil {
		return fmt.Errorf("failed to encode model: %w", err)
	}

	return nil
}

// initializeDefaultModel creates a default model for cold start
func (ad *AnomalyDetector) initializeDefaultModel() error {
	// Generate synthetic training data representing normal behavior
	normalData := ad.generateNormalBehaviorData(1000)

	// Train the forest
	ad.forest.Train(normalData)

	return nil
}

// generateNormalBehaviorData generates synthetic normal behavior patterns
func (ad *AnomalyDetector) generateNormalBehaviorData(numSamples int) [][]float64 {
	rand.Seed(time.Now().UnixNano())
	data := make([][]float64, numSamples)

	for i := 0; i < numSamples; i++ {
		// Generate features representing normal behavior
		features := []float64{
			// avg_interval: 1-30 seconds (normal human browsing)
			1.0 + rand.Float64()*29.0,
			// interval_variance: low variance for humans
			rand.Float64() * 5.0,
			// timing_entropy: moderate entropy
			0.3 + rand.Float64()*0.4,
			// path_entropy: moderate to high for normal browsing
			0.4 + rand.Float64()*0.4,
			// overall_entropy: balanced
			0.35 + rand.Float64()*0.4,
			// request_count: 5-50 per session
			5.0 + rand.Float64()*45.0,
			// unique_paths: 3-20
			3.0 + rand.Float64()*17.0,
			// error_rate: low for normal users
			rand.Float64() * 0.1,
			// key_op_ratio: balanced
			0.2 + rand.Float64()*0.3,
			// user_agents: typically 1-2
			1.0 + rand.Float64()*1.0,
			// payload_similarity: varied
			rand.Float64(),
		}
		data[i] = features
	}

	return data
}

// DetectAnomaly analyzes a behavior profile and returns an anomaly score
func (ad *AnomalyDetector) DetectAnomaly(profile *BehaviorProfile) *AnomalyScore {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	// Extract features from profile
	features := extractFeatures(profile)

	// Calculate anomaly score using Isolation Forest
	score := ad.forest.AnomalyScore(features)

	// Determine anomaly type and reasons
	anomalyType, reasons := ad.analyzeAnomaly(profile, features, score)

	// Generate recommendation
	recommendation := ad.generateRecommendation(score, anomalyType)

	// Cache the score
	ad.forest.AnomalyScores[profile.ClientIP] = score

	return &AnomalyScore{
		Score:          score,
		Confidence:     ad.calculateConfidence(profile),
		AnomalyType:    anomalyType,
		Reasons:        reasons,
		Recommendation: recommendation,
	}
}

// Train trains the Isolation Forest on the provided data
func (f *IsolationForest) Train(data [][]float64) {
	f.Trees = make([]*IsolationTree, f.NumTrees)

	for i := 0; i < f.NumTrees; i++ {
		// Sample subset of data
		sample := f.subsample(data)

		// Build isolation tree
		tree := &IsolationTree{
			PathLength: make(map[string]float64),
		}
		tree.Root = f.buildTree(sample, 0)
		f.Trees[i] = tree
	}
}

// subsample creates a random subsample of the data
func (f *IsolationForest) subsample(data [][]float64) [][]float64 {
	n := len(data)
	sampleSize := f.SampleSize
	if n < sampleSize {
		sampleSize = n
	}

	// Fisher-Yates shuffle for random sampling
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	for i := 0; i < sampleSize; i++ {
		j := i + rand.Intn(n-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	sample := make([][]float64, sampleSize)
	for i := 0; i < sampleSize; i++ {
		sample[i] = data[indices[i]]
	}

	return sample
}

// buildTree recursively builds an isolation tree
func (f *IsolationForest) buildTree(data [][]float64, depth int) *IsolationNode {
	n := len(data)

	// Base cases
	if depth >= f.MaxDepth || n <= 1 {
		return &IsolationNode{
			IsLeaf: true,
			Size:   n,
		}
	}

	// All samples have same values
	if f.allSame(data) {
		return &IsolationNode{
			IsLeaf: true,
			Size:   n,
		}
	}

	// Randomly select feature and split value
	numFeatures := len(data[0])
	feature := rand.Intn(numFeatures)

	minVal, maxVal := f.getFeatureRange(data, feature)
	if minVal == maxVal {
		return &IsolationNode{
			IsLeaf: true,
			Size:   n,
		}
	}

	splitValue := minVal + rand.Float64()*(maxVal-minVal)

	// Split data
	leftData, rightData := f.splitData(data, feature, splitValue)

	return &IsolationNode{
		IsLeaf:       false,
		SplitFeature: feature,
		SplitValue:   splitValue,
		Size:         n,
		Left:         f.buildTree(leftData, depth+1),
		Right:        f.buildTree(rightData, depth+1),
	}
}

// AnomalyScore calculates the anomaly score for a sample
func (f *IsolationForest) AnomalyScore(sample []float64) float64 {
	totalPathLength := 0.0

	for _, tree := range f.Trees {
		pathLength := f.pathLength(sample, tree.Root, 0)
		totalPathLength += pathLength
	}

	avgPathLength := totalPathLength / float64(f.NumTrees)

	// Normalize using average path length of unsuccessful search in BST
	n := float64(f.SampleSize)
	c := 2.0*(math.Log(n-1)+0.5772156649) - 2.0*(n-1)/n

	// Calculate anomaly score
	score := math.Pow(2, -avgPathLength/c)

	return score
}

// pathLength calculates the path length for a sample in a tree
func (f *IsolationForest) pathLength(sample []float64, node *IsolationNode, currentDepth float64) float64 {
	if node.IsLeaf {
		// Add average path length for remaining unbuilt tree
		return currentDepth + f.avgPathLength(node.Size)
	}

	if sample[node.SplitFeature] < node.SplitValue {
		return f.pathLength(sample, node.Left, currentDepth+1)
	}
	return f.pathLength(sample, node.Right, currentDepth+1)
}

// avgPathLength calculates average path length for n samples
func (f *IsolationForest) avgPathLength(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	return 2.0*(math.Log(float64(n-1))+0.5772156649) - 2.0*float64(n-1)/float64(n)
}

// Helper functions
func (f *IsolationForest) allSame(data [][]float64) bool {
	if len(data) <= 1 {
		return true
	}

	first := data[0]
	for i := 1; i < len(data); i++ {
		for j := range first {
			if data[i][j] != first[j] {
				return false
			}
		}
	}
	return true
}

func (f *IsolationForest) getFeatureRange(data [][]float64, feature int) (float64, float64) {
	minVal := data[0][feature]
	maxVal := data[0][feature]

	for _, sample := range data {
		if sample[feature] < minVal {
			minVal = sample[feature]
		}
		if sample[feature] > maxVal {
			maxVal = sample[feature]
		}
	}

	return minVal, maxVal
}

func (f *IsolationForest) splitData(data [][]float64, feature int, splitValue float64) ([][]float64, [][]float64) {
	var left, right [][]float64

	for _, sample := range data {
		if sample[feature] < splitValue {
			left = append(left, sample)
		} else {
			right = append(right, sample)
		}
	}

	return left, right
}

// analyzeAnomaly determines the type and reasons for anomaly
func (ad *AnomalyDetector) analyzeAnomaly(profile *BehaviorProfile, features []float64, score float64) (string, []string) {
	var anomalyType string
	var reasons []string

	// Check for bot-like behavior (too regular)
	if profile.EntropyMetrics.TimingEntropy < 0.2 {
		anomalyType = "bot_regular"
		reasons = append(reasons, "Timing pattern too regular (likely automated)")
	}

	// Check for bot-like behavior (artificially random)
	if profile.EntropyMetrics.TimingEntropy > 0.9 {
		anomalyType = "bot_random"
		reasons = append(reasons, "Timing pattern artificially random")
	}

	// Check for rapid requests
	if len(profile.RequestIntervals) > 0 && features[0] < 0.5 { // avg_interval < 0.5s
		anomalyType = "rapid_requests"
		reasons = append(reasons, "Request rate too fast for human")
	}

	// Check for user agent rotation
	if len(profile.UserAgentRotation) > 3 {
		anomalyType = "user_agent_rotation"
		reasons = append(reasons, "Suspicious user agent rotation detected")
	}

	// Check for crawler behavior
	if profile.SessionBehavior.UniquePathsCount > 50 {
		anomalyType = "crawler"
		reasons = append(reasons, "Excessive path exploration (crawler behavior)")
	}

	// Check for high error rate
	if profile.SessionBehavior.ErrorRate > 0.3 {
		anomalyType = "high_errors"
		reasons = append(reasons, "Abnormally high error rate")
	}

	// Default anomaly type if score is high but no specific pattern
	if score >= ad.threshold && anomalyType == "" {
		anomalyType = "general_anomaly"
		reasons = append(reasons, "Behavior deviates significantly from normal patterns")
	}

	return anomalyType, reasons
}

// calculateConfidence calculates confidence in the anomaly detection
func (ad *AnomalyDetector) calculateConfidence(profile *BehaviorProfile) float64 {
	confidence := 0.5 // Base confidence

	// Increase confidence with more data points
	dataPoints := len(profile.RequestIntervals)
	if dataPoints > 50 {
		confidence += 0.3
	} else if dataPoints > 20 {
		confidence += 0.2
	} else if dataPoints > 10 {
		confidence += 0.1
	}

	// Increase confidence if multiple indicators present
	indicators := 0
	if profile.EntropyMetrics.TimingEntropy < 0.2 || profile.EntropyMetrics.TimingEntropy > 0.9 {
		indicators++
	}
	if len(profile.UserAgentRotation) > 2 {
		indicators++
	}
	if profile.SessionBehavior.ErrorRate > 0.2 {
		indicators++
	}

	confidence += float64(indicators) * 0.1

	// Cap at 0.95
	if confidence > 0.95 {
		confidence = 0.95
	}

	return confidence
}

// generateRecommendation generates action recommendation based on score
func (ad *AnomalyDetector) generateRecommendation(score float64, anomalyType string) string {
	if score >= 0.9 {
		return "Block immediately - high confidence abuse"
	} else if score >= ad.threshold {
		switch anomalyType {
		case "bot_regular", "bot_random":
			return "Apply CAPTCHA or proof-of-work challenge"
		case "rapid_requests":
			return "Apply aggressive rate limiting"
		case "crawler":
			return "Apply crawler-specific rate limits"
		default:
			return "Monitor closely and apply moderate rate limiting"
		}
	} else if score >= 0.6 {
		return "Monitor for escalation"
	}
	return "No action required"
}

// UpdateModel performs online learning with new data
func (ad *AnomalyDetector) UpdateModel(newData []BehaviorDataPoint) error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Convert behavior data points to feature arrays
	var trainingData [][]float64
	for _, dataPoint := range newData {
		if dataPoint.Label { // Only train on confirmed anomalies
			trainingData = append(trainingData, dataPoint.Features)
		}
	}

	if len(trainingData) < 10 {
		return nil // Not enough data for update
	}

	// Retrain a subset of trees (online learning)
	numTreesUpdate := ad.forest.NumTrees / 10 // Update 10% of trees
	for i := 0; i < numTreesUpdate; i++ {
		treeIdx := rand.Intn(ad.forest.NumTrees)

		// Combine new data with synthetic normal data
		normalData := ad.generateNormalBehaviorData(100)
		combinedData := append(trainingData, normalData...)

		// Rebuild this tree
		sample := ad.forest.subsample(combinedData)
		ad.forest.Trees[treeIdx].Root = ad.forest.buildTree(sample, 0)
	}

	return nil
}
