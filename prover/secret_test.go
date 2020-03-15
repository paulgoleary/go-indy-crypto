package prover

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecretBasic(t *testing.T) {

	s1, err := MakeMasterSecret()
	require.NoError(t, err)
	defer s1.Free()

	s2, err := MakeMasterSecret()
	require.NoError(t, err)
	defer s2.Free()

	s1Json, err := s1.GetJson()
	require.NoError(t, err)
	s2Json, err := s2.GetJson()
	require.NoError(t, err)

	require.NotEqual(t, s1Json, s2Json)
}
