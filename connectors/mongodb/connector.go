package mongodb

import (
	"context"
	"encoding/json"
	"time"

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

func (c *Connector) Discovery(ctx context.Context, tablesList []string) ([]model.Table, error) {
	// Get the database
	db := c.client.Database(c.config.Database)

	// Create a map for quick lookups if tablesList is provided
	tableSet := make(map[string]bool)
	if len(tablesList) > 0 {
		for _, table := range tablesList {
			tableSet[table] = true
		}
	}

	// Get all collection names
	collections, err := db.ListCollectionNames(ctx, map[string]interface{}{})
	if err != nil {
		return nil, xerrors.Errorf("unable to list collections: %w", err)
	}

	var tables []model.Table
	for _, collectionName := range collections {
		// Skip collections not in the list if a list was provided
		if len(tablesList) > 0 && !tableSet[collectionName] {
			continue
		}

		// Get collection
		collection := db.Collection(collectionName)

		// Get a sample document to infer schema
		var sampleDoc map[string]interface{}
		err := collection.FindOne(ctx, map[string]interface{}{}).Decode(&sampleDoc)
		if err != nil && err != mongo.ErrNoDocuments {
			return nil, xerrors.Errorf("unable to get sample document from collection %s: %w", collectionName, err)
		}

		// Create columns from sample document
		var columns []model.ColumnSchema
		if sampleDoc != nil {
			for fieldName, value := range sampleDoc {
				columns = append(columns, model.ColumnSchema{
					Name: fieldName,
					Type: c.GuessColumnType(getMongoType(value)),
				})
			}
		}

		// Get document count for the collection
		count, err := collection.CountDocuments(ctx, map[string]interface{}{})
		if err != nil {
			return nil, xerrors.Errorf("unable to get document count for collection %s: %w", collectionName, err)
		}

		// Create table
		tables = append(tables, model.Table{
			Name:     collectionName,
			Columns:  columns,
			RowCount: int(count),
		})
	}

	return tables, nil
}

// getMongoType returns the MongoDB type of a value
func getMongoType(value interface{}) string {
	switch value.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case int32, int64:
		return "int"
	case bool:
		return "bool"
	case time.Time:
		return "date"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	default:
		return "string"
	}
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	// Parse the MongoDB query to get collection name
	var queryStruct struct {
		Collection string      `json:"collection"`
		Filter     interface{} `json:"filter"`
	}
	if err := json.Unmarshal([]byte(query), &queryStruct); err != nil {
		return nil, xerrors.Errorf("invalid MongoDB query format: %w", err)
	}

	// Get the database and collection
	db := c.client.Database(c.config.Database)
	collection := db.Collection(queryStruct.Collection)

	// Get a sample document from the collection
	var sampleDoc map[string]interface{}
	err := collection.FindOne(ctx, queryStruct.Filter).Decode(&sampleDoc)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, xerrors.Errorf("unable to get sample document: %w", err)
	}

	// If no document found, try to get any document from the collection
	if err == mongo.ErrNoDocuments {
		err = collection.FindOne(ctx, map[string]interface{}{}).Decode(&sampleDoc)
		if err != nil && err != mongo.ErrNoDocuments {
			return nil, xerrors.Errorf("unable to get sample document: %w", err)
		}
	}

	// Create column schemas from the sample document
	var columns []model.ColumnSchema
	if sampleDoc != nil {
		for fieldName, value := range sampleDoc {
			columns = append(columns, model.ColumnSchema{
				Name: fieldName,
				Type: c.GuessColumnType(getMongoType(value)),
			})
		}
	}

	return columns, nil
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
	// Get the database and collection
	db := c.client.Database(c.config.Database)
	collection := db.Collection(table.Name)

	// Set up find options to limit results
	findOptions := options.Find().
		SetLimit(5).                               // Limit to 5 documents
		SetSort(map[string]interface{}{"_id": -1}) // Sort by _id descending to get recent documents

	// Execute the query
	cursor, err := collection.Find(ctx, map[string]interface{}{}, findOptions)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute sample query: %w", err)
	}
	defer cursor.Close(ctx)

	// Collect results
	var results []map[string]any
	if err := cursor.All(ctx, &results); err != nil {
		return nil, xerrors.Errorf("unable to decode sample results: %w", err)
	}

	return results, nil
}
