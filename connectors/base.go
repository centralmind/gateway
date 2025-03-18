package connectors

import (
	"context"
	"database/sql"

	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

// BaseConnector provides common functionality for SQL-based connectors
type BaseConnector struct {
	DB *sqlx.DB
}

// TypeGuesser is an interface that each connector must implement to handle its specific type mapping
type TypeGuesser interface {
	GuessColumnType(sqlType string) model.ColumnType
}

// mapSQLTypeToColumnType converts SQL type to our ColumnType enum using connector-specific implementation
func (b *BaseConnector) mapSQLTypeToColumnType(guesser TypeGuesser, sqlType string) model.ColumnType {
	return guesser.GuessColumnType(sqlType)
}

// InferResultColumns provides a generic implementation for getting result column information
// This implementation works with any SQL database that supports the database/sql interfaces
func (b *BaseConnector) InferResultColumns(ctx context.Context, query string, guesser TypeGuesser) ([]model.ColumnSchema, error) {
	// Prepare the statement to get column information
	tx, err := b.DB.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return nil, xerrors.Errorf("unable to prepare statement: %w", err)
	}
	defer stmt.Close()

	prms := map[string]any{}
	for _, param := range stmt.Params {
		prms[param] = nil
	}
	// Execute the query to get column information
	// Note: This might execute a partial query, but most SQL databases are smart enough
	// to only fetch metadata without actually executing the full query
	rows, err := stmt.QueryContext(ctx, prms)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute statement: %w", err)
	}
	defer rows.Close()

	// Get column types from the result
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, xerrors.Errorf("unable to get column types: %w", err)
	}

	var columns []model.ColumnSchema
	for _, col := range colTypes {
		// Get the database-specific type name
		dbTypeName := col.DatabaseTypeName()

		columns = append(columns, model.ColumnSchema{
			Name: col.Name(),
			Type: b.mapSQLTypeToColumnType(guesser, dbTypeName),
		})
	}

	return columns, nil
}
