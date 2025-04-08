package mcpgenerator

import (
	"context"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/prompter"
	"github.com/centralmind/gateway/xcontext"
	"golang.org/x/xerrors"
)

func (s *MCPServer) EnableRawProtocol() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.server.DeleteTools("list_tables", "discover_data", "prepare_query", "query")
	s.server.AddTool(mcp.NewTool(
		"list_tables",
		mcp.WithDescription(fmt.Sprintf(`Return list of tables that available for data in %s database.
This is usually first this agent shall call.
`, s.connector.Config().Type())),
	), s.listTables)
	s.server.AddTool(mcp.NewTool(
		"discover_data",
		mcp.WithDescription(fmt.Sprintf(`Discover data structure for connected %s gateway.
tables_list parameter is comma separated table to fetch data samples.
Disovery better to call with a list of interested tables, since it will load all their samples.
`, s.connector.Config().Type())),
		mcp.WithString("tables_list"),
	), s.discoverData)
	s.server.AddTool(mcp.NewTool(
		"prepare_query",
		mcp.WithDescription(fmt.Sprintf(`Verify query and prepare output structure for query in %s database.
This tool shall be executed before query, to examine output structure and verify that query is correct.
`, s.connector.Config().Type())),
		mcp.WithString("query", mcp.Required()),
	), s.prepareQuery)
	s.server.AddTool(mcp.NewTool(
		"query",
		mcp.WithDescription(fmt.Sprintf("Query data structure for connected %s gateway", s.connector.Config().Type())),
		mcp.WithString("query", mcp.Required()),
	), s.query)
}

func (s *MCPServer) query(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	resData, err := s.connector.Query(
		ctx,
		model.Endpoint{Query: request.Params.Arguments["query"].(string)},
		make(map[string]any),
	)
	if err != nil {
		return nil, xerrors.Errorf("unable to infer query: %w", err)
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
		Text: fmt.Sprintf("Found %v records-(s).", len(res)),
	})
	for _, record := range res {
		content = append(content, mcp.TextContent{
			Type: "text",
			Text: prompter.Yamlify(record),
		})
	}
	return &mcp.CallToolResult{
		Content: content,
	}, nil
}

func (s *MCPServer) prepareQuery(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	resSchema, err := s.connector.InferQuery(ctx, request.Params.Arguments["query"].(string))
	if err != nil {
		return nil, xerrors.Errorf("unable to infer query: %w", err)
	}
	var content []mcp.Content
	content = append(content, mcp.TextContent{
		Type: "text",
		Text: fmt.Sprintf("Query has a %v column-(s).", len(resSchema)),
	})
	content = append(content, mcp.TextContent{
		Type: "text",
		Text: prompter.Yamlify(resSchema),
	})
	return &mcp.CallToolResult{
		Content: content,
	}, nil
}

func (s *MCPServer) discoverData(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := s.connector.Discovery(ctx, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to discover data: %w", err)
	}
	var content []mcp.Content
	content = append(content, mcp.TextContent{
		Type: "text",
		Text: fmt.Sprintf("Found a %v tables-(s).", len(data)),
	})
	allTables, err := s.connector.Discovery(ctx, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to discover all tables: %w", err)
	}

	tablesList, _ := request.Params.Arguments["tables_list"].(string)

	tableSet := map[string]bool{}

	for _, table := range strings.Split(tablesList, ",") {
		tableSet[table] = true
	}
	if len(tablesList) == 0 {
		for _, table := range allTables {
			tableSet[table.Name] = true
		}
	}
	var tablesToGenerate []prompter.TableData
	for _, table := range allTables {
		if !tableSet[table.Name] {
			continue
		}
		sample, err := s.connector.Sample(ctx, table)
		if err != nil {
			return nil, xerrors.Errorf("unable to discover sample: %w", err)
		}
		tablesToGenerate = append(tablesToGenerate, prompter.TableData{
			Columns:  table.Columns,
			Name:     table.Name,
			Sample:   sample,
			RowCount: table.RowCount,
		})
	}

	content = append(content, mcp.TextContent{
		Type: "text",
		Text: prompter.TablesPrompt(tablesToGenerate, prompter.SchemaFromConfig(s.connector.Config())),
	})

	return &mcp.CallToolResult{
		Content: content,
	}, nil
}

func (s *MCPServer) listTables(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := s.connector.Discovery(ctx, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to discover data: %w", err)
	}

	var content []mcp.Content
	content = append(content, mcp.TextContent{
		Type: "text",
		Text: fmt.Sprintf("Found %v records-(s).", len(data)),
	})
	for _, record := range data {
		schema := prompter.SchemaFromConfig(s.connector.Config())
		if schema != "" {
			record.Name = fmt.Sprintf("%v.%v", schema, record.Name)
		}
		content = append(content, mcp.TextContent{
			Type: "text",
			Text: prompter.Yamlify(record),
		})
	}
	return &mcp.CallToolResult{
		Content: content,
	}, nil
}
