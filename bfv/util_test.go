package bfv

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"testing"
)

func TestMatmul(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.DefaultPostQuantumParams[0])
	encoder := bfv.NewEncoder(params)
	evaluationKey := rlwe.EvaluationKey{}
	evaluator := bfv.NewEvaluator(params, evaluationKey)

	NewUtil(params, encoder, evaluator)
}
