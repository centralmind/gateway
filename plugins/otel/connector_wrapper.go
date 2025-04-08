package otel

import (
	"context"
	"fmt"
	"time"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/xcontext"

	"github.com/centralmind/gateway/model"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	trace_provider "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Connector struct {
	inner  connectors.Connector
	config Config
	tp     *trace_provider.TracerProvider
}

func (c Connector) Config() connectors.Config {
	return c.inner.Config()
}

func (c Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.inner.InferQuery(ctx, query)
}

func (c Connector) Ping(ctx context.Context) error {
	return c.inner.Ping(ctx)
}

func (c Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	tracer := c.tp.Tracer("database-connector")
	ctx, span := tracer.Start(ctx, endpoint.MCPMethod,
		trace.WithAttributes(
			attribute.String("api.http_path", endpoint.HTTPPath),
			attribute.String("api.mcp_method", endpoint.MCPMethod),
			attribute.String("db.query", endpoint.Query),
			attribute.String("db.system", fmt.Sprintf("%T", c.inner)),
		),
	)
	defer span.End()

	// Capture query parameters in the span
	for key, value := range params {
		span.SetAttributes(attribute.String("db.param."+key, fmt.Sprintf("%v", value)))
	}

	claims := xcontext.Claims(ctx)
	for key, value := range claims {
		span.SetAttributes(attribute.String("auth.claim."+key, fmt.Sprintf("%v", value)))
	}

	startTime := time.Now()
	result, err := c.inner.Query(ctx, endpoint, params)
	elapsedTime := time.Since(startTime)

	// Log execution time
	span.SetAttributes(attribute.Float64("db.execution_time_ms", float64(elapsedTime.Milliseconds())))

	if err != nil {
		span.SetStatus(codes.Error, "Query failed")
		span.RecordError(err)
		return nil, err
	}

	// Capture the number of rows returned
	span.SetAttributes(attribute.Int("db.rows_returned", len(result)))
	return result, nil
}

func (c Connector) Discovery(ctx context.Context, tablesList []string) ([]model.Table, error) {
	return c.inner.Discovery(ctx, tablesList)
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	return c.inner.Sample(ctx, table)
}
