package appliance

import (
	"context"
	"fmt"
	"io"

	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/api"
	appliancepkg "github.com/appgate/sdpctl/pkg/appliance"
	"github.com/appgate/sdpctl/pkg/configuration"
	"github.com/appgate/sdpctl/pkg/docs"
	"github.com/appgate/sdpctl/pkg/factory"
	"github.com/appgate/sdpctl/pkg/util"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type resolveNameOpts struct {
	Config       *configuration.Config
	Out          io.Writer
	Client       func(c *configuration.Config) (*openapi.APIClient, error)
	Appliance    func(c *configuration.Config) (*appliancepkg.Appliance, error)
	debug        bool
	json         bool
	applianceID  string
	resourceName string
}

func NewResolveNameCmd(f *factory.Factory) *cobra.Command {
	opts := resolveNameOpts{
		Config:    f.Config,
		Client:    f.APIClient,
		Appliance: f.Appliance,
		debug:     f.Config.Debug,
		Out:       f.IOOutWriter,
	}
	var cmd = &cobra.Command{
		Use:     "resolve-name [<appliance-id>] --resolve-name=query",
		Short:   docs.ApplianceResolveNameDoc.Short,
		Long:    docs.ApplianceResolveNameDoc.Long,
		Example: docs.ApplianceResolveNameDoc.ExampleString(),
		Args: func(cmd *cobra.Command, args []string) error {
			a, err := opts.Appliance(opts.Config)
			if err != nil {
				return err
			}
			ctx := context.Background()
			filter := map[string]map[string]string{
				"filter": {
					"function": "gateway",
				},
			}
			if len(args) != 1 {
				opts.applianceID, err = appliancepkg.PromptSelect(ctx, a, filter)
				if err != nil {
					return err
				}
				return nil
			}

			// Validate UUID if the argument is applied
			uuidArg := args[0]
			_, err = uuid.Parse(uuidArg)
			if err != nil {
				log.WithField("error", err).Info("Invalid ID. Please select appliance instead")
				uuidArg, err = appliancepkg.PromptSelect(ctx, a, filter)
				if err != nil {
					return err
				}
			}
			opts.applianceID = uuidArg

			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return resolveNameRun(c, args, &opts)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "Display in JSON format")
	cmd.Flags().StringVar(&opts.resourceName, "resource-name", "", "The resource name to test on the Gateway. (Required)")
	cmd.MarkFlagRequired("resource-name")

	return cmd
}

func resolveNameRun(cmd *cobra.Command, args []string, opts *resolveNameOpts) error {
	client, err := opts.Client(opts.Config)
	if err != nil {
		return err
	}
	token, err := opts.Config.GetBearTokenHeaderValue()
	if err != nil {
		return err
	}

	ctx := context.Background()
	body := openapi.InlineObject2{
		ResourceName: openapi.PtrString(opts.resourceName),
	}
	result, response, err := client.AppliancesApi.AppliancesIdTestResolverNamePost(ctx, opts.applianceID).InlineObject2(body).Authorization(token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	if opts.json {
		return util.PrintJSON(opts.Out, result)
	}
	for _, ip := range result.GetIps() {
		fmt.Fprintln(opts.Out, ip)
	}

	fmt.Fprintln(opts.Out, result.GetError())

	return nil
}
