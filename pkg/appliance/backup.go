package appliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/api"
	"github.com/appgate/sdpctl/pkg/appliance/backup"
	"github.com/appgate/sdpctl/pkg/configuration"
	"github.com/appgate/sdpctl/pkg/filesystem"
	"github.com/appgate/sdpctl/pkg/prompt"
	"github.com/appgate/sdpctl/pkg/tui"
	"github.com/appgate/sdpctl/pkg/util"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	mpb "github.com/vbauerster/mpb/v7"
	"golang.org/x/sync/errgroup"
)

var (
	DefaultBackupDestination = filepath.Join(filesystem.DownloadDir(), "appgate", "backup")
)

type BackupOpts struct {
	Config        *configuration.Config
	Appliance     func(*configuration.Config) (*Appliance, error)
	Out           io.Writer
	SpinnerOut    func() io.Writer
	Destination   string
	With          []string
	AllFlag       bool
	PrimaryFlag   bool
	CurrentFlag   bool
	Timeout       time.Duration
	NoInteractive bool
	FilterFlag    map[string]map[string]string
	Quiet         bool
	CiMode        bool
}

func PrepareBackup(opts *BackupOpts) error {
	log.WithField("destination", opts.Destination).Info("Preparing backup")

	if IsOnAppliance() {
		return fmt.Errorf("This should not be executed on an appliance")
	}

	opts.Destination = filesystem.AbsolutePath(opts.Destination)
	if err := os.MkdirAll(opts.Destination, 0700); err != nil {
		return err
	}

	return nil
}

func PerformBackup(cmd *cobra.Command, args []string, opts *BackupOpts) (map[string]string, error) {
	spinnerOut := opts.SpinnerOut()
	backupIDs := make(map[string]string)
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	var err error
	opts.CiMode, err = cmd.Flags().GetBool("ci-mode")
	if err != nil {
		return nil, err
	}

	audit := util.InSlice("audit", opts.With)
	logs := util.InSlice("logs", opts.With)

	app, err := opts.Appliance(opts.Config)
	if err != nil {
		return backupIDs, err
	}
	token, err := opts.Config.GetBearTokenHeaderValue()
	if err != nil {
		return backupIDs, err
	}
	backupEnabled, err := backupEnabled(ctx, app.APIClient, token, opts.NoInteractive)
	if err != nil {
		if opts.NoInteractive {
			return backupIDs, errors.New("Backup failed due to error while --no-interactive flag is set")
		}
		return backupIDs, fmt.Errorf("Failed to determine backup option: %w", err)
	}
	if !backupEnabled {
		if opts.NoInteractive {
			return backupIDs, errors.New("Using '--no-interactive' flag while backup API is disabled. Use the 'sdpctl appliance backup api' command to enable it before trying again.")
		}
		return backupIDs, errors.New("Backup API is disabled in the collective. Use the 'sdpctl appliance backup api' command to enable it.")
	}

	appliances, err := app.List(ctx, nil)
	if err != nil {
		return backupIDs, err
	}

	var toBackup []openapi.Appliance
	if opts.AllFlag {
		toBackup = appliances
	} else {
		hostname, _ := opts.Config.GetHost()
		nullFilter := map[string]map[string]string{
			"include": {},
			"exclude": {},
		}
		if reflect.DeepEqual(opts.FilterFlag, nullFilter) || opts.FilterFlag == nil {
			opts.FilterFlag = util.ParseFilteringFlags(cmd.Flags(), DefaultCommandFilter)
		}

		if opts.PrimaryFlag || opts.NoInteractive {
			pc, err := FindPrimaryController(appliances, hostname)
			if err != nil {
				log.Warn("failed to determine primary controller")
			} else {
				idFilter := []string{}
				if len(opts.FilterFlag["include"]["id"]) > 0 {
					idFilter = strings.Split(opts.FilterFlag["include"]["id"], FilterDelimiter)
				}
				idFilter = append(idFilter, pc.GetId())
				opts.FilterFlag["include"]["id"] = strings.Join(idFilter, FilterDelimiter)
			}
		}

		if opts.CurrentFlag {
			cc, err := FindCurrentController(appliances, hostname)
			if err != nil {
				log.Warn("failed to determine current controller")
			} else {
				idFilter := []string{}
				if len(opts.FilterFlag["include"]["id"]) > 0 {
					idFilter = strings.Split(opts.FilterFlag["include"]["id"], FilterDelimiter)
				}
				idFilter = append(idFilter, cc.GetId())
				opts.FilterFlag["include"]["id"] = strings.Join(idFilter, FilterDelimiter)
			}
		}

		if len(args) > 0 {
			fInclude := []string{}
			if len(opts.FilterFlag["include"]["name"]) > 0 {
				fInclude = strings.Split(opts.FilterFlag["include"]["name"], FilterDelimiter)
			}
			fInclude = append(fInclude, args...)
			opts.FilterFlag["include"]["name"] = strings.Join(fInclude, FilterDelimiter)
		}

		if !reflect.DeepEqual(nullFilter, opts.FilterFlag) {
			toBackup = append(toBackup, FilterAppliances(appliances, opts.FilterFlag)...)
		}
	}

	if len(toBackup) <= 0 {
		toBackup, err = BackupPrompt(appliances, []openapi.Appliance{})
		if err != nil {
			return nil, err
		}
	}

	// Filter offline appliances
	initialStats, _, err := app.Stats(ctx)
	if err != nil {
		return backupIDs, err
	}
	toBackup, offline, _ := FilterAvailable(toBackup, initialStats.GetData())

	for _, v := range offline {
		log.WithField("appliance", v.GetName()).Info("Skipping appliance. Appliance is offline.")
	}

	if len(toBackup) <= 0 {
		fmt.Fprintln(opts.Out, "No appliances to backup. Either no appliance was selected or the selected appliances are offline.")
		return nil, nil
	}

	if !opts.Quiet {
		msg, err := showBackupSummary(opts.Destination, toBackup)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(opts.Out, "%s\n", msg)
	}

	type backedUp struct {
		applianceID, backupID, destination string
	}

	var (
		wg           sync.WaitGroup
		count        = len(toBackup)
		backups      = make(chan backedUp, count)
		errorChannel = make(chan error, count)
		backupAPI    = backup.New(app.APIClient, app.Token, opts.Config.Version)
		progressBars *mpb.Progress
	)

	if !opts.CiMode {
		progressBars = mpb.NewWithContext(ctx, mpb.WithOutput(spinnerOut), mpb.WithWaitGroup(&wg))
		defer progressBars.Wait()
	}
	wg.Add(count)

	retryStatus := func(ctx context.Context, applianceID, backupID string) error {
		return backoff.Retry(func() error {
			status, err := backupAPI.Status(ctx, applianceID, backupID)
			if err != nil {
				return err
			}
			if status != backup.Done {
				return fmt.Errorf("Backup not done for appliance %s, got %s", applianceID, status)
			}
			return nil
		}, backoff.NewExponentialBackOff())
	}

	b := func(appliance openapi.Appliance) (backedUp, error) {
		b := backedUp{applianceID: appliance.GetId()}
		b.backupID, err = backupAPI.Initiate(ctx, b.applianceID, logs, audit)
		if err != nil {
			return b, err
		}
		if err := retryStatus(ctx, b.applianceID, b.backupID); err != nil {
			return b, err
		}
		file, err := backupAPI.Download(ctx, b.applianceID, b.backupID)
		if err != nil {
			return b, err
		}

		b.destination = filepath.Join(opts.Destination, fmt.Sprintf("appgate_backup_%s_%s.bkp", strings.ReplaceAll(appliance.GetName(), " ", "_"), time.Now().Format("20060102_150405")))
		out, err := os.Create(b.destination)
		if err != nil {
			return b, err
		}
		if _, err := io.Copy(out, file); err != nil {
			return b, err
		}
		file.Close()
		out.Close()
		if err := os.Remove(file.Name()); err != nil {
			return b, err
		}
		return b, nil
	}

	for _, a := range toBackup {
		go func(appliance openapi.Appliance) {
			defer wg.Done()
			var bar *mpb.Bar
			if !opts.CiMode {
				bar = tui.AddDefaultSpinner(progressBars, appliance.GetName(), backup.Processing, backup.Done)
			}
			backedUp, err := b(appliance)
			if err != nil {
				if !opts.CiMode {
					bar.Abort(false)
				}
				errorChannel <- fmt.Errorf("could not backup %s %s", appliance.GetName(), err)
				return
			}
			if !opts.CiMode {
				bar.Increment()
			}
			backups <- backedUp
		}(a)
	}

	go func() {
		wg.Wait()
		close(backups)
		close(errorChannel)
	}()

	for b := range backups {
		backupIDs[b.applianceID] = b.backupID
		log.WithField("file", b.destination).Info("Wrote backup file")
	}
	var result error
	for err := range errorChannel {
		log.Error(err)
		result = multierror.Append(err)
	}

	return backupIDs, result
}

func CleanupBackup(opts *BackupOpts, IDs map[string]string) error {
	if IDs == nil || len(IDs) <= 0 {
		return errors.New("Command finished, but no appliances were backed up. See log for more details")
	}
	app, err := opts.Appliance(opts.Config)
	if err != nil {
		return err
	}
	token, err := opts.Config.GetBearTokenHeaderValue()
	if err != nil {
		return err
	}
	ctxWithGPGAccept := context.WithValue(context.Background(), openapi.ContextAcceptHeader, fmt.Sprintf("application/vnd.appgate.peer-v%d+gpg", opts.Config.Version))
	g, ctx := errgroup.WithContext(ctxWithGPGAccept)
	log.WithField("backup_ids", IDs).Info("Cleaning up...")
	for appID, bckID := range IDs {
		ID := appID
		backupID := bckID
		g.Go(func() error {
			res, err := app.APIClient.ApplianceBackupApi.AppliancesIdBackupBackupIdDelete(ctx, ID, backupID).Authorization(token).Execute()
			if err != nil {
				return api.HTTPErrorResponse(res, err)
			}
			return nil
		})
	}
	g.Wait()
	log.Info("Finished cleanup")
	fmt.Fprint(opts.Out, "Backup complete!\n\n")

	return nil
}

func BackupPrompt(appliances []openapi.Appliance, preSelected []openapi.Appliance) ([]openapi.Appliance, error) {
	names := []string{}
	preSelectNames := []string{}

	selectorNameMap := map[string]string{}
	appendFunctions := func(appliance openapi.Appliance) string {
		name := appliance.GetName()
		activeFunctions := GetActiveFunctions(appliance)
		selectorName := fmt.Sprintf("%s ( %s )", name, strings.Join(activeFunctions, ", "))
		selectorNameMap[selectorName] = name
		return selectorName
	}

	// Filter out all but Controllers, LogServers and Portals
	appliances = FilterAppliances(appliances, map[string]map[string]string{
		"include": {"function": strings.Join([]string{FunctionController, FunctionLogServer, FunctionPortal}, FilterDelimiter)},
	})

	for _, a := range appliances {
		selectorName := appendFunctions(a)
		for _, ps := range preSelected {
			if a.GetName() == ps.GetName() {
				preSelectNames = append(preSelectNames, selectorName)
			}
		}
		names = append(names, selectorName)
	}

	qs := &survey.MultiSelect{
		PageSize: len(appliances),
		Message:  "select appliances to backup:",
		Options:  names,
		Default:  preSelectNames,
	}
	var selectedEntries []string
	if err := prompt.SurveyAskOne(qs, &selectedEntries); err != nil {
		return nil, err
	}
	selected := []string{}
	for _, selectorName := range selectedEntries {
		selected = append(selected, selectorNameMap[selectorName])
	}
	log.WithField("appliances", selected).Info("selected appliances for backup")

	result := FilterAppliances(appliances, map[string]map[string]string{
		"include": {
			"name": strings.Join(selected, FilterDelimiter),
		},
	})

	return result, nil
}

func backupEnabled(ctx context.Context, client *openapi.APIClient, token string, noInteraction bool) (bool, error) {
	settings, _, err := client.GlobalSettingsApi.GlobalSettingsGet(ctx).Authorization(token).Execute()
	if err != nil {
		return false, err
	}
	enabled := settings.GetBackupApiEnabled()
	if !enabled && !noInteraction {
		log.Warn("Backup API is disabled on the appliance.")
		var shouldEnable bool
		q := &survey.Confirm{
			Message: "Backup API is disabled on the appliance. Do you want to enable it now?",
			Default: true,
		}
		if err := prompt.SurveyAskOne(q, &shouldEnable, survey.WithValidator(survey.Required)); err != nil {
			return false, err
		}

		if shouldEnable {
			settings.SetBackupApiEnabled(true)
			password, err := prompt.PasswordConfirmation("The passphrase to encrypt Appliance Backups when backup API is used:")
			if err != nil {
				return false, err
			}
			settings.SetBackupPassphrase(password)
			result, err := client.GlobalSettingsApi.GlobalSettingsPut(ctx).GlobalSettings(*settings).Authorization(token).Execute()
			if err != nil {
				return false, api.HTTPErrorResponse(result, err)
			}
			newSettings, response, err := client.GlobalSettingsApi.GlobalSettingsGet(ctx).Authorization(token).Execute()
			if err != nil {
				return false, api.HTTPErrorResponse(response, err)
			}
			enabled = newSettings.GetBackupApiEnabled()
		}
	}

	return enabled, nil
}

func showBackupSummary(dest string, appliances []openapi.Appliance) (string, error) {
	type ApplianceStub struct {
		Name string
		ID   string
	}
	type SummaryStub struct {
		Appliances  []ApplianceStub
		Destination string
	}

	const message = `
Will perform backup on the following appliances:

{{- range .Appliances }}
 - {{ .Name -}}
{{ end }}

Backup destination is {{ .Destination }}
`

	data := SummaryStub{Destination: dest}
	for _, app := range appliances {
		data.Appliances = append(data.Appliances, ApplianceStub{
			Name: app.GetName(),
			ID:   app.GetId(),
		})
	}

	t := template.Must(template.New("").Parse(message))
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}

	return tpl.String(), nil
}
