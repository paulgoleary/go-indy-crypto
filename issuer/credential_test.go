package issuer

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func makeTestCredentialDef(t *testing.T) *CredentialDef {

	credBuilder, err := MakeCredSchemaBuilder()
	require.NoError(t, err)
	require.NotNil(t, credBuilder)

	err = credBuilder.AddAttrib("name")
	require.NoError(t, err)
	err = credBuilder.AddAttrib("sex")
	require.NoError(t, err)
	err = credBuilder.AddAttrib("age")
	require.NoError(t, err)
	err = credBuilder.AddAttrib("height")
	require.NoError(t, err)

	//for i := 0; i < 100; i++ {
	//	err = credBuilder.AddAttrib(fmt.Sprintf("attrib%v", i))
	//	require.NoError(t, err)
	//}

	credSchema, err := credBuilder.Finalize()
	require.NoError(t, err)
	require.NotNil(t, credSchema)
	defer credSchema.Close()

	nonCredBuilder, err := MakeNonCredSchemaBuilder()
	require.NoError(t, err)
	require.NotNil(t, nonCredBuilder)

	err = nonCredBuilder.AddAttrib("master_secret")
	require.NoError(t, err)

	nonCredSchema, err := nonCredBuilder.Finalize()
	require.NoError(t, err)
	require.NotNil(t, nonCredSchema)
	defer nonCredSchema.Close()

	credDef, err := MakeCredentialDef(credSchema, nonCredSchema, true)
	require.NoError(t, err)
	require.NotNil(t, credDef)

	return credDef
}

func TestCredentialBasic(t *testing.T) {

	credDef := makeTestCredentialDef(t)
	defer credDef.Close()

	testJson := func(f func() (string, error), name string) {
		pkJsonStr, err := f()
		require.NoError(t, err)
		println(fmt.Sprintf("%v, size %v: %v", name, len(pkJsonStr), pkJsonStr))
	}

	testJson(credDef.GetPublicKeyJson, "CRED PUBLIC KEY")
	testJson(credDef.GetSecretKeyJson, "CRED SECRET KEY")
	testJson(credDef.GetProofJson, "CRED PROOF")
}
