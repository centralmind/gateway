package cli

import (
	"context"
	"fmt"
	"github.com/centralmind/gateway/logger"
	"github.com/centralmind/gateway/model"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centralmind/gateway/connectors"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

func Connection() *cobra.Command {
	var configPath string
	var tables string
	var samplePath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify connection config",
		Long:  "Verify that connection is valid, by pinging connector",
		Args:  cobra.MaximumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Configure header
			logrus.Info("\r\n")
			logrus.Info("🚀 Verify Discovery Process")

			configRaw, err := os.ReadFile(configPath)
			if err != nil {
				return err
			}

			tablesData, err := loadTablesData(splitTables(tables), configRaw)
			if err != nil {
				return xerrors.Errorf("unable to verify connection: %w", err)
			}
			for _, t := range tablesData {
				logrus.Infof("Schema for: %s", t.Name)
				printTableSchema(t)
				logrus.Infof("Data sample for: %s", t.Name)
				printTableSample(t.Columns, t.Sample)
			}

			if err := saveToFile(samplePath, yamlify(tablesData)); err != nil {
				logrus.Error("Failed to save tables sample data", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "connection.yaml", "Path to connection yaml file")
	cmd.Flags().StringVar(&tables, "tables", "", "Comma-separated list of tables to include (e.g. 'table1,table2,table3')")
	cmd.Flags().StringVar(&samplePath, "llm-log", filepath.Join(logger.DefaultLogDir(), "sample.yaml"), "Path to save the raw LLM response")

	return cmd
}

func splitTables(tables string) []string {
	var tablesList []string
	if tables != "" {
		tablesList = strings.Split(tables, ",")
		// Trim spaces from table names
		for i := range tablesList {
			tablesList[i] = strings.TrimSpace(tablesList[i])
		}
	}
	return tablesList
}

type dbType struct {
	Type string `yaml:"type" json:"type"`
}

func loadTablesData(tablesList []string, configRaw any) ([]TableData, error) {
	logrus.Info("Step 1: Read configs")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	connector, err := connectors.New(inferType(configRaw), configRaw)
	if err != nil {
		return nil, xerrors.Errorf("unable to create connector: %s: %w", inferType(configRaw), err)
	}
	logrus.Info("✅ Step 1 completed. Done.")
	logrus.Info("\r\n")

	logrus.Info("Step 2: Discover data")
	allTables, err := connector.Discovery(ctx)
	if err != nil {
		return nil, err
	}

	tableSet := map[string]bool{}

	for _, table := range tablesList {
		tableSet[table] = true
	}
	if len(tablesList) == 0 {
		for _, table := range allTables {
			tableSet[table.Name] = true
		}
	}

	// Show discovered tables
	logrus.Info("Discovered Tables:")
	for _, table := range allTables {
		if tableSet[table.Name] {
			logrus.Infof("  - "+cyan+"%s"+reset+": "+yellow+"%d"+reset+" columns, "+yellow+"%d"+reset+" rows", table.Name, len(table.Columns), table.RowCount)
		}
	}

	// Check if any tables were found after filtering
	var filteredTablesCount int
	for range tableSet {
		filteredTablesCount++
	}
	if filteredTablesCount == 0 {
		return nil, xerrors.Errorf("error: no tables found to process. Please verify your database connection and table selection criteria")
	}

	logrus.Info("✅ Step 2 completed. Done.")
	logrus.Info("\r\n")
	// Sample data
	logrus.Info("Step 3: Sample data from tables")
	var tablesToGenerate []TableData
	for _, table := range allTables {
		if !tableSet[table.Name] {
			continue
		}
		sample, err := connector.Sample(ctx, table)
		if err != nil {
			return nil, err
		}
		tablesToGenerate = append(tablesToGenerate, TableData{
			Columns:  table.Columns,
			Name:     table.Name,
			Sample:   sample,
			RowCount: table.RowCount,
		})
	}

	// Show sampled data
	logrus.Info("Data Sampling Results:")
	for _, table := range tablesToGenerate {
		logrus.Infof("  - "+cyan+"%s"+reset+": "+yellow+"%d"+reset+" rows sampled", table.Name, len(table.Sample))
	}
	logrus.Info("✅ Step 3 completed. Done.")
	logrus.Info("\r\n")
	return tablesToGenerate, nil
}

func inferType(configRaw any) string {
	var typ dbType
	switch v := configRaw.(type) {
	case string:
		if err := yaml.Unmarshal([]byte(v), &typ); err != nil {
			return "unknown"
		}
	case []byte:
		if err := yaml.Unmarshal(v, &typ); err != nil {
			return "unknown"
		}
	}
	return typ.Type
}

func printTableSchema(table TableData) {
	tw := tablewriter.NewWriter(os.Stdout)
	tw.SetHeader([]string{"Name", "Type", "Key"})
	tw.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	tw.SetCenterSeparator("|")
	tw.SetColumnSeparator("|")
	tw.SetRowSeparator("-")

	for _, col := range table.Columns {
		primaryKey := red + "NO" + reset
		if col.PrimaryKey {
			primaryKey = green + "YES" + reset
		}
		tw.Append([]string{
			col.Name,
			string(col.Type),
			primaryKey,
		})
	}

	tw.Render()
}

func printTableSample(columns []model.ColumnSchema, sample []map[string]any) {
	tw := tablewriter.NewWriter(os.Stdout)

	var headers []string
	for _, col := range columns {
		headers = append(headers, col.Name)
	}
	tw.SetHeader(headers)
	tw.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	tw.SetCenterSeparator("*")
	tw.SetRowLine(true)
	tw.SetColumnSeparator("|")
	tw.SetRowSeparator("-")
	for _, row := range sample {
		var rowC []string
		for _, c := range headers {
			rowC = append(rowC, fmt.Sprintf("%v", row[c]))
		}
		tw.Append(rowC)
	}
	tw.Render()
}
