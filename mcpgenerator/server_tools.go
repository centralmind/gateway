package mcpgenerator

import (
	"context"
	"fmt"
	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/xcontext"
)

func (s *MCPServer) Tools() []model.Endpoint {
	return s.tools
}

func (s *MCPServer) SetTools(tools []model.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for _, t := range tools {
		names = append(names, t.MCPMethod)
	}
	s.server.DeleteTools(names...)
	for _, endpoint := range tools {
		var opts []mcp.ToolOption
		for _, col := range endpoint.Params {
			if col.Required {
				opts = append(opts, ArgumentOption(col, mcp.Required()))
			} else {
				opts = append(opts, ArgumentOption(col))
			}
		}

		s.server.AddTool(mcp.NewTool(
			endpoint.MCPMethod,
			opts...,
		), s.endpoint(endpoint))
	}
	s.tools = tools
}

func (s *MCPServer) endpoint(endpoint model.Endpoint) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		arg := request.Params.Arguments
		for _, param := range endpoint.Params {
			if _, ok := arg[param.Name]; !ok {
				arg[param.Name] = nil
			}
		}
		resData, err := s.connector.Query(ctx, endpoint, request.Params.Arguments)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Unable to query: %s", err),
					},
				},
				IsError: true,
			}, nil
		}
		var res []map[string]interface{}
	MAIN:
		for _, row := range resData {
			for _, interceptor := range s.interceptors {
				r, skip := interceptor.Process(row, xcontext.Headers(ctx))
				if skip {
					continue MAIN
				}
				row = r
			}
			res = append(res, row)
		}
		var content []mcp.Content
		content = append(content, mcp.TextContent{
			Type: "text",
			Text: fmt.Sprintf("Found a %v row-(s) in %s.", len(res), endpoint.Group),
		})
		for _, row := range res {
			content = append(content, mcp.TextContent{
				Type: "text",
				Text: jsonify(row),
			})
		}

		return &mcp.CallToolResult{
			Content: content,
		}, nil
	}
}

func ArgumentOption(col model.EndpointParams, opts ...mcp.PropertyOption) mcp.ToolOption {
	opts = append(opts, mcp.Title(fmt.Sprintf("Column %s", col.Name)))
	opts = append(opts, func(m map[string]interface{}) {
		m["default"] = col.Default
	})

	switch col.Type {
	case "integer", "double", "float", "number":
		return mcp.WithNumber(col.Name, opts...)

	case "string":
		return mcp.WithString(col.Name, opts...)

	case "bool", "boolean":
		return mcp.WithBoolean(col.Name, opts...)

	default:
		return mcp.WithString(col.Name)
	}
}
