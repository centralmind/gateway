package cli

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/centralmind/gateway/mcpgenerator"
	gw_model "github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/restgenerator"
)

func StartCommand() *cobra.Command {
	var gatewayParams string
	var addr string
	var servers string
	var rawMode bool
	var disableSwagger bool
	var prefix string
	var dbDSN string
	var dbType string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start gateway",
		Args:  cobra.MatchAll(cobra.ExactArgs(0)),
	}
	cmd.PersistentFlags().StringVar(&gatewayParams, "config", "./gateway.yaml", "path to yaml file with gateway configuration")
	cmd.PersistentFlags().StringVar(&addr, "addr", ":9090", "addr for gateway")
	cmd.PersistentFlags().StringVar(&servers, "servers", "", "comma-separated list of additional server URLs for Swagger UI (e.g., https://dev1.example.com,https://dev2.example.com)")

	cmd.Flags().StringVar(&dbDSN, "dsn", "", "database DSN")
	cmd.Flags().StringVar(&dbType, "type", "postgres", "type of database to use")
	cmd.Flags().BoolVar(&disableSwagger, "disable-swagger", false, "disable Swagger UI")
	cmd.Flags().StringVar(&prefix, "prefix", "", "prefix for protocol path")
	cmd.Flags().BoolVar(&rawMode, "raw", false, "enable as raw protocol")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		var err error
		var gw *gw_model.Config
		if dbDSN != "" {
			gw = &gw_model.Config{
				API: gw_model.APIParams{
					Name:        "Auto API",
					Description: "Raw api for agent access",
					Version:     "0.0.1",
				},
				Database: gw_model.Database{
					Type:       dbType,
					Connection: dbDSN,
					Tables:     nil,
				},
			}
		} else {
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

		// Create the list of server addresses for RegisterRoutes
		serverAddresses := []string{}

		// Add additional servers from the --servers flag if provided
		if servers != "" {
			additionalServers := strings.Split(servers, ",")
			for _, server := range additionalServers {
				serverAddresses = append(serverAddresses, strings.TrimSpace(server))
			}
		}

		if len(serverAddresses) == 0 {
			serverAddresses = append(serverAddresses, fmt.Sprintf("http://localhost%s", addr))
		}

		if err := a.RegisterRoutes(mux, disableSwagger, rawMode, serverAddresses...); err != nil {
			return err
		}

		srv, err := mcpgenerator.New(*gw)
		if err != nil {
			return xerrors.Errorf("unable to init mcp generator: %w", err)
		}

		if rawMode {
			if err := mcpgenerator.AddRawProtocol(*gw, srv.Server()); err != nil {
				return xerrors.Errorf("unable to add raw mcp protocol: %w", err)
			}
		}

		resURL, _ := url.JoinPath(serverAddresses[0], "/", prefix, "sse")
		sse := srv.ServeSSE(serverAddresses[0], prefix)
		mux.Handle(path.Join("/", prefix, "sse"), sse)
		mux.Handle(path.Join("/", prefix, "message"), sse)

		logrus.Infof("MCP server is running at: %s", resURL)
		if !disableSwagger {
			logrus.Infof("Open API is running at: %s/%s", serverAddresses[0], prefix)
		}

		return http.ListenAndServe(addr, mux)
	}

	RegisterCommand(cmd, Stdio(&gatewayParams))
	return cmd
}

// RegisterCommand is like parent.AddCommand(child), but also
// makes chaining of PersistentPreRunE and PersistentPreRun
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
