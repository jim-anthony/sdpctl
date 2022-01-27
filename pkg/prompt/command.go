package prompt

import (
	"context"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	appliancepkg "github.com/appgate/appgatectl/pkg/appliance"
)

func SelectAppliance(ctx context.Context, a *appliancepkg.Appliance, filter map[string]map[string]string) (string, error) {
	appliances, err := a.List(ctx, filter)
	if err != nil {
		return "", err
	}
	stats, _, err := a.Stats(ctx)
	if err != nil {
		return "", err
	}
	appliances, _, err = appliancepkg.FilterAvailable(appliances, stats.GetData())
	if err != nil {
		return "", err
	}

	names := []string{}
	for _, a := range appliances {
		names = append(names, fmt.Sprintf("%s - %s - %s", a.GetName(), a.GetSiteName(), a.GetTags()))
	}
	qs := &survey.Select{
		PageSize: len(appliances),
		Message:  "select appliance:",
		Options:  names,
	}
	selectedIndex := 0
	if err := SurveyAskOne(qs, &selectedIndex, survey.WithValidator(survey.Required)); err != nil {
		return "", err
	}

	appliance := appliances[selectedIndex]
	return appliance.GetId(), nil
}
