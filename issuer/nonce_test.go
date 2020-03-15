package issuer

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNonceBasic(t *testing.T) {

	n1, err := MakeNonce()
	require.NoError(t, err)
	require.NotNil(t, n1)
	defer n1.Close()

	n2, err := MakeNonce()
	require.NoError(t, err)
	require.NotNil(t, n1)
	defer n2.Close()

	n1Json, err := n1.GetJson()
	require.NoError(t, err)
	n2Json, err := n2.GetJson()
	require.NoError(t, err)

	require.NotEqual(t, n1Json, n2Json)
}
