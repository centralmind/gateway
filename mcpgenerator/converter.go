package mcpgenerator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/plugins"
	"github.com/centralmind/gateway/server"
	"golang.org/x/xerrors"
)

type MCPServer struct {
	server *server.MCPServer
}

func New(
	schema model.Config,
) (*MCPServer, error) {
	srv := server.NewMCPServer("mcp-data-gateway", "0.0.1")

	var interceptors []plugins.Interceptor
	for k, v := range schema.Plugins {
		plugin, err := plugins.New(k, v)
		if err != nil {
			return nil, err
		}
		interceptor, ok := plugin.(plugins.Interceptor)
		if !ok {
			continue
		}
		interceptors = append(interceptors, interceptor)
	}
	connector, err := connectors.New(schema.Database.Type, schema.Database.Connection)
	if err != nil {
		return nil, xerrors.Errorf("unable to init connector: %w", err)
	}
	connector, err = plugins.Wrap(schema.Plugins, connector)
	if err != nil {
		return nil, xerrors.Errorf("unable to init connector plugins: %w", err)
	}
	for _, endpoint := range schema.Database.Endpoints {
		var opts []mcp.ToolOption
		for _, col := range endpoint.Params {
			if col.Required {
				opts = append(opts, ArgumentOption(col, mcp.Required()))
			} else {
				opts = append(opts, ArgumentOption(col))
			}
		}

		srv.AddTool(mcp.NewTool(
			endpoint.MCPMethod,
			opts...,
		), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			arg := request.Params.Arguments
			for _, param := range endpoint.Params {
				if _, ok := arg[param.Name]; !ok {
					arg[param.Name] = nil
				}
			}
			res, err := connector.Query(ctx, endpoint, request.Params.Arguments)
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
		})
	}

	return &MCPServer{
		server: srv,
	}, nil
}

func jsonify(data any) string {
	res, _ := json.Marshal(data)
	return string(res)
}

func (s *MCPServer) ServeSSE(addr string, prefix string) *server.SSEServer {
	return server.NewSSEServer(s.server, addr, prefix)
}

func (s *MCPServer) ServeStdio() *server.StdioServer {
	return server.NewStdioServer(s.server)
}

func (s *MCPServer) Server() *server.MCPServer {
	return s.server
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
