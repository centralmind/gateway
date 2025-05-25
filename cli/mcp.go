package cli

import (
	"context"
	"github.com/centralmind/gateway/connectors"
	"os"
	"path/filepath"

	"github.com/centralmind/gateway/logger"
	"github.com/centralmind/gateway/mcpgenerator"
	gw_model "github.com/centralmind/gateway/model"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

func Stdio(configPath *string) *cobra.Command {
	var logFile string
	var rawMode bool
	var dbDSN string
	res := &cobra.Command{
		Use:   "stdio",
		Short: "MCP gateway via std-io",
		Long: `Start the MCP (Message Communication Protocol) gateway using standard input/output.

This command enables communication with AI agents through stdin/stdout streams,
making it ideal for integration with other processes or tools that can communicate
via standard streams. The MCP protocol provides structured message exchange
optimized for AI agent interactions.`,
		Args: cobra.MatchAll(cobra.ExactArgs(0)),
		RunE: func(cmd *cobra.Command, args []string) error {
			var gw *gw_model.Config
			var err error

			if dbDSN != "" {
				// If DSN is provided, use it directly
				gw, err = gw_model.FromDSN(dbDSN)
			} else {
				// Otherwise load from config file
				gwRaw, err := os.ReadFile(*configPath)
				if err != nil {
					return xerrors.Errorf("unable to read yaml config file: %w", err)
				}
				gw, err = gw_model.FromYaml(gwRaw)
				if err != nil {
					return xerrors.Errorf("unable to parse config file: %w", err)
				}
			}

			srv, err := mcpgenerator.New(gw.Plugins)
			if err != nil {
				return xerrors.Errorf("unable to init mcp generator: %w", err)
			}
			connector, err := connectors.New(gw.Database.Type, gw.Database.Connection)
			if err != nil {
				return xerrors.Errorf("unable to init connector: %w", err)
			}
			if err := srv.SetConnector(connector); err != nil {
				return xerrors.Errorf("unable to set connector: %w", err)
			}
			if rawMode {
				srv.EnableRawProtocol()
			}
			allEndpoints := gw.Database.GetAllEndpoints()
			if len(allEndpoints) > 0 {
				srv.SetTools(allEndpoints)
			}

			return srv.ServeStdio().Listen(context.Background(), os.Stdin, os.Stdout)
		},
	}

	res.Flags().BoolVar(&rawMode, "raw", true, "Enable raw protocol mode optimized for AI agents")
	res.Flags().StringVar(&logFile, "log-file", filepath.Join(logger.DefaultLogDir(), "mcp.log"), "Path to log file for MCP gateway operations")
	res.Flags().StringVarP(&dbDSN, "connection-string", "C", "", "Database connection string (DSN) for direct database connection")
	return res
}
