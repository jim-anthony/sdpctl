package appliance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/api"
	"github.com/hashicorp/go-version"
	"golang.org/x/sync/errgroup"
)

// Appliance is a wrapper around the APIClient for common functions around the appliance API that
// will be used within several commands.
type Appliance struct {
	APIClient           *openapi.APIClient
	HTTPClient          *http.Client
	Token               string
	UpgradeStatusWorker WaitForUpgradeStatus
	ApplianceStats      WaitForApplianceStatus
}

// List from the appgate sdp collective
// Filter is applied in app after getting all the appliances because the auto generated API screws up the 'filterBy' command
func (a *Appliance) List(ctx context.Context, filter map[string]map[string]string) ([]openapi.Appliance, error) {
	appliances, response, err := a.APIClient.AppliancesApi.AppliancesGet(ctx).OrderBy("name").Authorization(a.Token).Execute()
	if err != nil {
		return nil, api.HTTPErrorResponse(response, err)
	}
	return FilterAppliances(appliances.GetData(), filter), nil
}

const (
	//lint:file-ignore U1000 All available upgrade statuses
	UpgradeStatusIdle        = "idle"
	UpgradeStatusStarted     = "started"
	UpgradeStatusDownloading = "downloading"
	UpgradeStatusVerifying   = "verifying"
	UpgradeStatusReady       = "ready"
	UpgradeStatusInstalling  = "installing"
	UpgradeStatusSuccess     = "success"
	UpgradeStatusFailed      = "failed"
	fileInProgress           = "InProgress"
	FileReady                = "Ready"
	FileFailed               = "Failed"
)

func (a *Appliance) UpgradeStatus(ctx context.Context, applianceID string) (*openapi.AppliancesIdUpgradeDelete200Response, error) {
	status, response, err := a.APIClient.ApplianceUpgradeApi.AppliancesIdUpgradeGet(ctx, applianceID).Authorization(a.Token).Execute()
	if err != nil {
		return status, api.HTTPErrorResponse(response, err)
	}
	return status, nil
}

type UpgradeStatusResult struct {
	Status, Details, Name string
}

// UpgradeStatusMap return a map with appliance.id, UpgradeStatusResult
func (a *Appliance) UpgradeStatusMap(ctx context.Context, appliances []openapi.Appliance) (map[string]UpgradeStatusResult, error) {
	type result struct {
		id, status, details, name string
	}
	g, ctx := errgroup.WithContext(ctx)
	c := make(chan result)
	for _, appliance := range appliances {
		i := appliance
		g.Go(func() error {
			status, err := a.UpgradeStatus(ctx, i.GetId())
			if err != nil {
				return fmt.Errorf("Could not read status of %s %w", i.GetId(), err)
			}
			select {
			case c <- result{
				id:      i.GetId(),
				status:  status.GetStatus(),
				details: status.GetDetails(),
				name:    i.GetName(),
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}
	go func() {
		g.Wait()
		close(c)
	}()
	m := make(map[string]UpgradeStatusResult)
	for r := range c {
		m[r.id] = UpgradeStatusResult{
			Status:  r.status,
			Details: r.details,
			Name:    r.name,
		}
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return m, nil
}

func (a *Appliance) UpgradeCancel(ctx context.Context, applianceID string) error {
	response, err := a.APIClient.ApplianceUpgradeApi.AppliancesIdUpgradeDelete(ctx, applianceID).Authorization(a.Token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	return nil
}

func (a *Appliance) Stats(ctx context.Context) (*openapi.StatsAppliancesList, *http.Response, error) {
	status, response, err := a.APIClient.ApplianceStatsApi.StatsAppliancesGet(ctx).Authorization(a.Token).Execute()
	if err != nil {
		return status, response, api.HTTPErrorResponse(response, err)
	}
	return status, response, nil
}

var ErrFileNotFound = errors.New("File not found")

// FileStatus Get the status of a File uploaded to the current Controller.
func (a *Appliance) FileStatus(ctx context.Context, filename string) (*openapi.File, error) {
	f, r, err := a.APIClient.ApplianceUpgradeApi.FilesFilenameGet(ctx, filename).Authorization(a.Token).Execute()
	if err != nil {
		if r.StatusCode == http.StatusNotFound {
			return f, fmt.Errorf("%q: %w", filename, ErrFileNotFound)
		}
		return f, api.HTTPErrorResponse(r, err)
	}
	return f, nil
}

// UploadFile directly to the current Controller. Note that the File is stored only on the current Controller, not synced between Controllers.
func (a *Appliance) UploadFile(ctx context.Context, r io.Reader, headers map[string]string) error {
	httpClient := a.HTTPClient
	cfg := a.APIClient.GetConfig()
	url, err := cfg.ServerURLWithContext(ctx, "ApplianceUpgradeApiService.FilesPut")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, url+"/files", r)
	if err != nil {
		return err
	}
	for k, v := range cfg.DefaultHeader {
		req.Header.Add(k, v)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", a.Token)
	response, err := httpClient.Do(req)
	if err != nil {
		if response == nil {
			return fmt.Errorf("no response during upload %w", err)
		}
		if response.StatusCode == http.StatusConflict {
			return fmt.Errorf("already exists %w", err)
		}
		return api.HTTPErrorResponse(response, err)
	}
	defer response.Body.Close()
	return nil
}

func (a *Appliance) UploadToController(ctx context.Context, url, filename string) error {
	response, err := a.APIClient.ApplianceUpgradeApi.FilesPost(ctx).Authorization(a.Token).FilesGetRequest1(openapi.FilesGetRequest1{
		Url:      url,
		Filename: filename,
	}).Execute()
	if err != nil {
		if response == nil {
			return fmt.Errorf("no response during upload %w", err)
		}
		if response.StatusCode == http.StatusConflict {
			return fmt.Errorf("already exists %w", err)
		}
		return api.HTTPErrorResponse(response, err)
	}

	return nil
}

func (a *Appliance) ListFiles(ctx context.Context) ([]openapi.File, error) {
	list, response, err := a.APIClient.ApplianceUpgradeApi.FilesGet(ctx).Authorization(a.Token).Execute()
	if err != nil {
		return nil, api.HTTPErrorResponse(response, err)
	}
	return list.GetData(), nil
}

// DeleteFile Delete a File from the current Controller.
func (a *Appliance) DeleteFile(ctx context.Context, filename string) error {
	response, err := a.APIClient.ApplianceUpgradeApi.FilesFilenameDelete(ctx, filename).Authorization(a.Token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	return nil
}

func (a *Appliance) PrepareFileOn(ctx context.Context, filename, id string, devKeyring bool) error {
	u := openapi.ApplianceUpgrade{
		ImageUrl: filename,
	}
	if devKeyring {
		// Only set dev keyring if it is true
		// will prevent errors with older api-version that don't support dev-keyring
		u.DevKeyring = openapi.PtrBool(devKeyring)
	}
	_, r, err := a.APIClient.ApplianceUpgradeApi.AppliancesIdUpgradePreparePost(ctx, id).ApplianceUpgrade(u).Authorization(a.Token).Execute()
	if err != nil {
		if r == nil {
			return fmt.Errorf("No response during prepare %w", err)
		}
		if r.StatusCode == http.StatusConflict {
			return fmt.Errorf("Upgrade in progress on %s %w", id, err)
		}
		return api.HTTPErrorResponse(r, err)
	}
	return nil
}

func (a *Appliance) UpdateAppliance(ctx context.Context, id string, appliance openapi.Appliance) error {
	_, response, err := a.APIClient.AppliancesApi.AppliancesIdPut(ctx, id).Appliance(appliance).Authorization(a.Token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	return nil
}

func (a *Appliance) DisableController(ctx context.Context, id string, appliance openapi.Appliance) error {
	appliance.Controller.Enabled = openapi.PtrBool(false)

	return a.UpdateAppliance(ctx, id, appliance)
}

func (a *Appliance) EnableController(ctx context.Context, id string, appliance openapi.Appliance) error {
	appliance.Controller.Enabled = openapi.PtrBool(true)

	return a.UpdateAppliance(ctx, id, appliance)
}

func (a *Appliance) UpdateMaintenanceMode(ctx context.Context, id string, value bool) (string, error) {
	o := openapi.AppliancesIdMaintenancePostRequest{
		Enabled: value,
	}
	m, response, err := a.APIClient.ApplianceMaintenanceApi.AppliancesIdMaintenancePost(ctx, id).AppliancesIdMaintenancePostRequest(o).Authorization(a.Token).Execute()
	if err != nil {
		return "", api.HTTPErrorResponse(response, err)
	}
	return m.GetId(), nil
}

func (a *Appliance) EnableMaintenanceMode(ctx context.Context, id string) (string, error) {
	return a.UpdateMaintenanceMode(ctx, id, true)
}

func (a *Appliance) DisableMaintenanceMode(ctx context.Context, id string) (string, error) {
	return a.UpdateMaintenanceMode(ctx, id, false)
}

func (a *Appliance) UpgradeComplete(ctx context.Context, id string, SwitchPartition bool) error {
	o := openapi.AppliancesIdUpgradeCompletePostRequest{
		SwitchPartition: openapi.PtrBool(SwitchPartition),
	}
	_, response, err := a.APIClient.ApplianceUpgradeApi.AppliancesIdUpgradeCompletePost(ctx, id).AppliancesIdUpgradeCompletePostRequest(o).Authorization(a.Token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	return nil
}

func (a *Appliance) UpgradeSwitchPartition(ctx context.Context, id string) error {
	_, response, err := a.APIClient.ApplianceUpgradeApi.AppliancesIdUpgradeSwitchPartitionPost(ctx, id).Authorization(a.Token).Execute()
	if err != nil {
		return api.HTTPErrorResponse(response, err)
	}
	return nil
}

func (a *Appliance) GetPeerAPIVersion(applianceVersion *version.Version) int {
	versionMap := map[string]int{
		"5.1": 12,
		"5.2": 13,
		"5.3": 14,
		"5.4": 15,
		"5.5": 16,
		"6.0": 17,
		"6.1": 18,
	}

	var candidate int
	for k, v := range versionMap {
		av, _ := version.NewVersion(k)

		if applianceVersion.GreaterThanOrEqual(av) && v > candidate {
			candidate = v
		}
	}
	return candidate
}
