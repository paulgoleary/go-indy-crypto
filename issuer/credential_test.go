package issuer

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBasic(t *testing.T) {

	credBuilder, err := MakeSchemaBuilder()
	require.NoError(t, err)
	require.NotNil(t, credBuilder)
	defer credBuilder.Close()

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

}
