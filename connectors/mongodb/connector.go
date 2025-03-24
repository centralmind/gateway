package mongodb

import (
	"context"
	"encoding/json"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		// Create MongoDB client options
		clientOptions := options.Client().ApplyURI(cfg.ConnectionString())

		// Create MongoDB client
		client, err := mongo.Connect(context.Background(), clientOptions)
		if err != nil {
			return nil, xerrors.Errorf("unable to connect to MongoDB: %w", err)
		}

		// Ping the database to verify connection
		if err := client.Ping(context.Background(), nil); err != nil {
			return nil, xerrors.Errorf("unable to ping MongoDB: %w", err)
		}

		return &Connector{
			config: cfg,
			client: client,
		}, nil
	})
}

// Connector implements the connectors.Connector interface for MongoDB
type Connector struct {
	config Config
	client *mongo.Client
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// Ping checks if MongoDB is reachable
func (c Connector) Ping(ctx context.Context) error {
	if err := c.client.Ping(ctx, nil); err != nil {
		return xerrors.Errorf("unable to ping MongoDB: %w", err)
	}
	return nil
}

func (c *Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	// Get the database
	db := c.client.Database(c.config.Database)

	// Parse the MongoDB query to get collection name and filter
	var query struct {
		Collection string      `json:"collection"`
		Filter     interface{} `json:"filter"`
	}
	if err := json.Unmarshal([]byte(endpoint.Query), &query); err != nil {
		return nil, xerrors.Errorf("invalid MongoDB query format: %w", err)
	}

	// Get collection
	collection := db.Collection(query.Collection)

	// Process parameters
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}

	// Replace parameters in the filter
	filter := replaceParams(query.Filter, processed)

	// Execute the query
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query: %w", err)
	}
	defer cursor.Close(ctx)

	// Collect results
	var results []map[string]any
	if err := cursor.All(ctx, &results); err != nil {
		return nil, xerrors.Errorf("unable to decode results: %w", err)
	}

	return results, nil
}

// replaceParams replaces parameter placeholders in the MongoDB query with actual values
func replaceParams(filter interface{}, params map[string]any) interface{} {
	switch v := filter.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if _, ok := value.(string); ok {
				if paramValue, exists := params[key]; exists {
					v[key] = paramValue
				}
			} else {
				v[key] = replaceParams(value, params)
			}
		}
	case []interface{}:
		for i, value := range v {
			v[i] = replaceParams(value, params)
		}
	}
	return filter
}

func (c *Connector) Discovery(ctx context.Context) ([]model.Table, error) {
	return nil, nil
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return nil, nil
}

func (c *Connector) GuessColumnType(mongoType string) model.ColumnType {
	switch mongoType {
	case "string":
		return model.TypeString
	case "number", "double", "decimal":
		return model.TypeNumber
	case "int", "long":
		return model.TypeInteger
	case "bool":
		return model.TypeBoolean
	case "date":
		return model.TypeDatetime
	case "object":
		return model.TypeObject
	case "array":
		return model.TypeArray
	default:
		return model.TypeString
	}
}

func (c *Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	return nil, nil
}
