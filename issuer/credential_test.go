package issuer

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBasic(t *testing.T) {

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
	defer credDef.Close()

	pkJsonStr, err := credDef.GetPublicKeyJson()
	require.NoError(t, err)
	println(pkJsonStr)

	skJsonStr, err := credDef.GetSecretKeyJson()
	require.NoError(t, err)
	println(skJsonStr)

	proofJsonStr, err := credDef.GetProofJson()
	require.NoError(t, err)
	println(proofJsonStr)

}
