package issuer

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRevocationBasic(t *testing.T) {

	credDef := makeTestCredentialDef(t)

	revokeDef, err := MakeRevocationRegistryDef(credDef, 10, false)
	require.NoError(t, err)
	require.NotNil(t, revokeDef)
	defer revokeDef.Free()

	testJson := func(f func() (string, error), name string) {
		pkJsonStr, err := f()
		require.NoError(t, err)
		println(fmt.Sprintf("%v, size %v: %v", name, len(pkJsonStr), pkJsonStr))
	}

	testJson(revokeDef.GetPublicKeyJson, "REVOKE PUBLIC KEY")
	testJson(revokeDef.GetSecretKeyJson, "REVOKE SECRET KEY")
	testJson(revokeDef.GetRevocationRegJson, "REVOKE REG DEF")
	testJson(revokeDef.GetRevocationTailsGenJson, "REVOKE TAILS GEN")
}
