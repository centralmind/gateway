package cli

import (
	"fmt"
	"github.com/centralmind/gateway/plugins"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/centralmind/gateway/mcpgenerator"
	gw_model "github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/restgenerator"
)

func StartCommand() *cobra.Command {
	var gatewayParams string
	var addr string
	var servers string
	var rawMode bool
	var roMode bool
	var disableSwagger bool
	var prefix string
	var dbDSN string
	var typ string
	var enableMCP bool
	var enableRestAPI bool

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start gateway",
		Long: `Start the Gateway server that provides both REST API and MCP SSE endpoints optimized for AI agents.

The server launches two main components:
1. REST API server with OpenAPI/Swagger documentation
2. MCP (Message Communication Protocol) SSE server for real-time event streaming

Upon successful startup, the terminal will display URLs for both services.`,
		Args: cobra.MatchAll(cobra.ExactArgs(0)),
	}
	cmd.PersistentFlags().StringVar(&gatewayParams, "config", "./gateway.yaml", "Path to YAML file with gateway configuration")
	cmd.PersistentFlags().StringVar(&addr, "addr", ":9090", "Address and port for the gateway server (e.g., ':9090', '127.0.0.1:8080')")
	cmd.PersistentFlags().StringVar(&servers, "servers", "", "Comma-separated list of additional server URLs for Swagger UI (e.g., 'https://dev1.example.com,https://dev2.example.com')")

	cmd.Flags().StringVarP(&dbDSN, "connection-string", "C", "", "Database connection string (DSN) for direct database connection")
	cmd.Flags().StringVar(&typ, "type", "", "Type of database to use (for example: postgres os mysql)")
	cmd.Flags().BoolVar(&disableSwagger, "disable-swagger", false, "Disable Swagger UI documentation")
	cmd.Flags().StringVar(&prefix, "prefix", "", "URL prefix for all API endpoints")
	cmd.Flags().BoolVar(&enableMCP, "mcp", true, "Start MCP SSE server")
	cmd.Flags().BoolVar(&enableRestAPI, "rest-api", true, "Start Rest API server")
	cmd.Flags().BoolVar(&rawMode, "raw", true, "Enable raw protocol mode optimized for AI agents")
	cmd.Flags().BoolVar(&roMode, "read-only", true, "Run queries on read-only mode")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		var err error
		var gw *gw_model.Config
		if dbDSN != "" {
			if typ == "" {
				typ = strings.Split(dbDSN, ":")[0]
			}
			// Create a default configuration when using direct database connection
			gw = &gw_model.Config{
				API: gw_model.APIParams{
					Name:        "Auto API",
					Description: "Raw api for agent access",
					Version:     "0.0.1",
				},
				Database: gw_model.Database{
					Type: typ,
					Connection: map[string]any{
						"conn_string": dbDSN,
						"is_readonly": roMode,
					},
					Endpoints: nil,
				},
			}
		} else {
			// Load configuration from YAML file
			gwRaw, err := os.ReadFile(gatewayParams)
			if err != nil {
				return xerrors.Errorf("unable to read yaml config file: %w", err)
			}
			gw, err = gw_model.FromYaml(gwRaw)
			if err != nil {
				return xerrors.Errorf("unable to parse config file: %w", err)
			}
		}
		mux := http.NewServeMux()
		a, err := restgenerator.New(*gw, prefix)

		if err != nil {
			return xerrors.Errorf("unable to init api: %w", err)
		}

		// Create the list of server addresses for API documentation and endpoints
		serverAddresses := []string{}

		// Add additional servers from the --servers flag if provided
		// These are used in Swagger UI to allow testing against different environments
		if servers != "" {
			additionalServers := strings.Split(servers, ",")
			for _, server := range additionalServers {
				serverAddresses = append(serverAddresses, strings.TrimSpace(server))
			}
		}

		// If no servers were specified, use localhost with the provided address
		if len(serverAddresses) == 0 {
			serverAddresses = append(serverAddresses, fmt.Sprintf("http://localhost%s", addr))
		}

		if err := a.RegisterRoutes(mux, disableSwagger, rawMode, serverAddresses...); err != nil {
			return err
		}

		// Initialize the MCP (Message Communication Protocol) generator
		// This provides real-time communication capabilities optimized for AI agents
		srv, err := mcpgenerator.New(gw.Database, gw.Plugins)
		if err != nil {
			return xerrors.Errorf("unable to init mcp generator: %w", err)
		}

		// Enable raw protocol mode for AI agent communication if specified
		if rawMode {
			srv.EnableRawProtocol()
		}
		if len(gw.Database.Endpoints) > 0 {
			srv.SetTools(gw.Database.Endpoints)
		}
		if !enableRestAPI && !enableMCP {
			logrus.Fatal("At least one of protocol must be enabled, nothing to start")
		}

		logrus.Infof("Gateway server started successfully!")
		if enableMCP {
			plugs, err := plugins.Plugins[plugins.MCPToolEnricher](gw.Plugins)
			if err != nil {
				return xerrors.Errorf("unable to load plugins: %w", err)
			}
			for _, plug := range plugs {
				plug.EnrichMCP(srv)
			}
			sse := srv.ServeSSE(serverAddresses[0], prefix)
			mux.Handle(path.Join("/", prefix, "sse"), sse)
			mux.Handle(path.Join("/", prefix, "message"), sse)
			// Set up SSE (Server-Sent Events) endpoints for real-time event streaming
			resURL, _ := url.JoinPath(serverAddresses[0], "/", prefix, "sse")
			logrus.Infof("MCP SSE server for AI agents is running at: %s", resURL)
		}

		if enableRestAPI {
			if !disableSwagger {
				swaggerURL := fmt.Sprintf("%s/%s", serverAddresses[0], prefix)
				logrus.Infof("REST API with Swagger UI is available at: %s", swaggerURL)
			}
		}

		return http.ListenAndServe(addr, mux)
	}

	RegisterCommand(cmd, Stdio(&gatewayParams))
	return cmd
}

// RegisterCommand registers a child command to a parent command while properly
// chaining their PersistentPreRunE and PersistentPreRun hooks.
// This ensures that both parent and child pre-run hooks are executed in the correct order.
//
// Unlike the standard cobra.Command.AddCommand method, this function properly handles
// the execution chain of pre-run hooks, making it suitable for complex command hierarchies.
func RegisterCommand(parent, child *cobra.Command) {
	parentPpre := parent.PersistentPreRunE
	childPpre := child.PersistentPreRunE
	if child.PersistentPreRunE == nil && child.PersistentPreRun != nil {
		childPpre = func(cmd *cobra.Command, args []string) error {
			child.PersistentPreRun(cmd, args)
			return nil
		}
	}
	if childPpre != nil {
		child.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			if parentPpre != nil {
				err := parentPpre(cmd, args)
				if err != nil {
					return xerrors.Errorf("cannot process parent PersistentPreRunE: %w", err)
				}
			}
			return childPpre(cmd, args)
		}
	} else if parentPpre != nil {
		child.PersistentPreRunE = parentPpre
	}
	parent.AddCommand(child)
}
