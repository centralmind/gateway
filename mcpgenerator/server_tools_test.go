package mcpgenerator

import (
	"context"
	"testing"

	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/model"
	"github.com/stretchr/testify/assert"
)

func TestSetToolsIncludesDescription(t *testing.T) {
	srv, err := New(nil)
	assert.NoError(t, err)
	ctx := context.Background()

	// initialize server to enable tools capabilities
	_ = srv.Server().HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))

	endpoint := model.Endpoint{
		MCPMethod:   "test_method",
		Description: "sample description",
		Params: []model.EndpointParams{
			{Name: "id", Type: "string"},
		},
	}

	srv.SetTools([]model.Endpoint{endpoint})

	resp := srv.Server().HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	listResp, ok := resp.(mcp.JSONRPCResponse)
	assert.True(t, ok)
	tools := listResp.Result.(mcp.ListToolsResult).Tools
	if assert.Len(t, tools, 1) {
		assert.Equal(t, "sample description", tools[0].Description)
	}
}
