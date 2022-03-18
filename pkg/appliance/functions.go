package appliance

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/appgate/sdp-api-client-go/api/v16/openapi"
	"github.com/appgate/sdpctl/pkg/hashcode"
	"github.com/appgate/sdpctl/pkg/util"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

const (
	FunctionController   = "controller"
	FunctionGateway      = "gateway"
	FunctionPortal       = "portal"
	FunctionConnector    = "connector"
	FunctionLogServer    = "logserver"
	FunctionLogForwarder = "logforwarder"
	FilterDelimiter      = "&"
)

// GroupByFunctions group appliances by function
func GroupByFunctions(appliances []openapi.Appliance) map[string][]openapi.Appliance {
	r := make(map[string][]openapi.Appliance)
	for _, a := range appliances {
		if v, ok := a.GetControllerOk(); ok && v.GetEnabled() {
			r[FunctionController] = append(r[FunctionController], a)
		}
		if v, ok := a.GetGatewayOk(); ok && v.GetEnabled() {
			r[FunctionGateway] = append(r[FunctionGateway], a)
		}
		if v, ok := a.GetPortalOk(); ok && v.GetEnabled() {
			r[FunctionPortal] = append(r[FunctionPortal], a)
		}
		if v, ok := a.GetConnectorOk(); ok && v.GetEnabled() {
			r[FunctionConnector] = append(r[FunctionConnector], a)
		}
		if v, ok := a.GetLogServerOk(); ok && v.GetEnabled() {
			r[FunctionLogServer] = append(r[FunctionLogServer], a)
		}
		if v, ok := a.GetLogForwarderOk(); ok && v.GetEnabled() {
			r[FunctionLogForwarder] = append(r[FunctionLogForwarder], a)
		}
	}
	return r
}

// ActiveFunctions returns a map of all active functions in the appliances.
func ActiveFunctions(appliances []openapi.Appliance) map[string]bool {
	functions := make(map[string]bool)
	for _, a := range appliances {
		res := GetActiveFunctions(a)
		if util.InSlice(FunctionController, res) {
			functions[FunctionController] = true
		}
		if util.InSlice(FunctionGateway, res) {
			functions[FunctionGateway] = true
		}
		if util.InSlice(FunctionPortal, res) {
			functions[FunctionPortal] = true
		}
		if util.InSlice(FunctionConnector, res) {
			functions[FunctionConnector] = true
		}
		if util.InSlice(FunctionLogServer, res) {
			functions[FunctionLogServer] = true
		}
		if util.InSlice(FunctionLogForwarder, res) {
			functions[FunctionLogForwarder] = true
		}
	}
	return functions
}

func GetActiveFunctions(appliance openapi.Appliance) []string {
	functions := []string{}

	if v, ok := appliance.GetControllerOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionController)
	}
	if v, ok := appliance.GetGatewayOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionGateway)
	}
	if v, ok := appliance.GetPortalOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionPortal)
	}
	if v, ok := appliance.GetConnectorOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionConnector)
	}
	if v, ok := appliance.GetLogServerOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionLogServer)
	}
	if v, ok := appliance.GetLogForwarderOk(); ok && v.GetEnabled() {
		functions = append(functions, FunctionLogForwarder)
	}

	return functions
}

// WithAdminOnPeerInterface List all appliances still using the peer interface for the admin API, this is now deprecated.
func WithAdminOnPeerInterface(appliances []openapi.Appliance) []openapi.Appliance {
	peer := make([]openapi.Appliance, 0)
	for _, a := range appliances {
		if _, ok := a.GetAdminInterfaceOk(); !ok {
			peer = append(peer, a)
		}
	}
	return peer
}

// FilterAvailable return lists of online, offline, errors that will be used during upgrade
func FilterAvailable(appliances []openapi.Appliance, stats []openapi.StatsAppliancesListAllOfData) ([]openapi.Appliance, []openapi.Appliance, error) {
	result := make([]openapi.Appliance, 0)
	offline := make([]openapi.Appliance, 0)
	var err error
	// filter out offline appliances
	for _, a := range appliances {
		for _, stat := range stats {
			if a.GetId() == stat.GetId() {
				if stat.GetOnline() {
					result = append(result, a)
				} else {
					offline = append(offline, a)
				}
			}
		}
	}
	for _, a := range offline {
		if v, ok := a.GetControllerOk(); ok && v.GetEnabled() {
			err = multierror.Append(err, fmt.Errorf("cannot start the operation since a controller %q is offline.", a.GetName()))
		}
		if v, ok := a.GetLogServerOk(); ok && v.GetEnabled() {
			err = multierror.Append(err, fmt.Errorf("cannot start the operation since a logserver %q is offline.", a.GetName()))
		}
	}
	return result, offline, err
}

// SplitAppliancesByGroup return a map of slices of appliances based on their active function and site.
// e.g All active gateways in the same site are grouped together.
func SplitAppliancesByGroup(appliances []openapi.Appliance) map[int][]openapi.Appliance {
	result := make(map[int][]openapi.Appliance)
	for _, a := range appliances {
		groupID := applianceGroupHash(a)
		result[groupID] = append(result[groupID], a)
	}
	return result
}

// maxInnerChunkSize represent how many appliance can be in each chunk
// this value is derived to how many goroutines is used when upgrading appliances simultaneously
const maxInnerChunkSize = 4

// ChunkApplianceGroup separates the result from SplitAppliancesByGroup into different slices based on the appliance
// functions and site configuration
func ChunkApplianceGroup(chunkSize int, applianceGroups map[int][]openapi.Appliance) [][]openapi.Appliance {
	if chunkSize == 0 {
		chunkSize = 2
	}
	// var chunks [][]openapi.Appliance
	chunks := make([][]openapi.Appliance, chunkSize)
	for i := range chunks {
		chunks[i] = make([]openapi.Appliance, 0)
	}
	// for consistency, we need to sort all input and output slices to generate a consistent result
	for id := range applianceGroups {
		sort.Slice(applianceGroups[id], func(i, j int) bool {
			return applianceGroups[id][i].GetName() < applianceGroups[id][j].GetName()
		})
	}

	keys := make([]int, 0, len(applianceGroups))
	for k := range applianceGroups {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	count := 0
	for _, slice := range applianceGroups {
		for range slice {
			count += 1
		}
	}

	for i := 0; i <= count; i++ {
		// select which initial slice we are going to put the appliance in
		// the appliance may be moved later if the slice ends up to big.
		index := i % chunkSize
		chunk := chunks[index]
		for _, groupID := range keys {
			slice := applianceGroups[groupID]
			if len(slice) > 0 {
				item, slice := slice[len(slice)-1], slice[:len(slice)-1]
				applianceGroups[groupID] = slice
				temp := make([]openapi.Appliance, 0)
				temp = append(temp, item)
				chunk = append(chunk, temp...)
			}
		}
		chunks[index] = chunk
	}

	// make sure we sort each slice for a consistent output and remove any empty slices.
	var r [][]openapi.Appliance
	for index := range chunks {
		sort.Slice(chunks[index], func(i, j int) bool {
			return chunks[index][i].GetName() < chunks[index][j].GetName()
		})

		if len(chunks[index]) > maxInnerChunkSize {
			r = append(r, chunkApplianceSlice(chunks[index], maxInnerChunkSize)...)
		} else if len(chunks[index]) > 0 {
			r = append(r, chunks[index])
		}
	}
	return r
}

func chunkApplianceSlice(slice []openapi.Appliance, chunkSize int) [][]openapi.Appliance {
	var chunks [][]openapi.Appliance
	for {
		if len(slice) == 0 {
			break
		}

		// necessary check to avoid slicing beyond
		// slice capacity
		if len(slice) < chunkSize {
			chunkSize = len(slice)
		}

		chunks = append(chunks, slice[0:chunkSize])
		slice = slice[chunkSize:]
	}

	return chunks
}

// applianceGroupHash return a unique id hash based on the active function of the appliance and their site ID.
func applianceGroupHash(appliance openapi.Appliance) int {
	var buf bytes.Buffer
	if v, ok := appliance.GetControllerOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "controller-", v.GetEnabled()))
		// we want to group all controllers to the same group
		return hashcode.String(buf.String())
	}
	if len(appliance.GetSite()) > 0 {
		buf.WriteString(appliance.GetSite())
	}
	if v, ok := appliance.GetLogForwarderOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "log_forwarder-", v.GetEnabled()))
	}
	if v, ok := appliance.GetLogServerOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "log_server-", v.GetEnabled()))
	}
	if v, ok := appliance.GetGatewayOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "gateway-", v.GetEnabled()))
	}
	if v, ok := appliance.GetConnectorOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "connector-", v.GetEnabled()))
	}
	if v, ok := appliance.GetPortalOk(); ok {
		buf.WriteString(fmt.Sprintf("%s-%t", "portal-", v.GetEnabled()))
	}

	return hashcode.String(buf.String())
}

func ActiveSitesInAppliances(slice []openapi.Appliance) int {
	keys := make(map[string]bool)
	for _, a := range slice {
		if v, ok := a.GetSiteOk(); ok {
			if _, ok := keys[*v]; !ok {
				keys[*v] = true
			}
		}
	}
	return len(keys)
}

func GetApplianceVersion(appliance openapi.Appliance, stats openapi.StatsAppliancesList) (*version.Version, error) {
	for _, s := range stats.GetData() {
		if s.GetId() == appliance.GetId() {
			return version.NewVersion(s.GetVersion())
		}
	}
	return nil, fmt.Errorf("could not determine appliance version of the primary controller %s", appliance.GetName())
}

// FindPrimaryController The given hostname should match one of the controller's actual admin hostname.
// Hostnames should be compared in a case insensitive way.
func FindPrimaryController(appliances []openapi.Appliance, hostname string) (*openapi.Appliance, error) {
	controllers := make([]openapi.Appliance, 0)
	type details struct {
		ID        string
		Hostnames []string
		Appliance openapi.Appliance
	}
	data := make(map[string]details)
	for _, a := range appliances {
		if v, ok := a.GetControllerOk(); ok && v.GetEnabled() {
			controllers = append(controllers, a)
		}
	}
	for _, controller := range controllers {
		var hostnames []string
		hostnames = append(hostnames, strings.ToLower(controller.GetPeerInterface().Hostname))
		if v, ok := controller.GetAdminInterfaceOk(); ok {
			hostnames = append(hostnames, strings.ToLower(v.GetHostname()))
		}
		if v, ok := controller.GetPeerInterfaceOk(); ok {
			hostnames = append(hostnames, strings.ToLower(v.GetHostname()))
		}
		data[controller.GetId()] = details{
			ID:        controller.GetId(),
			Hostnames: hostnames,
			Appliance: controller,
		}
	}
	count := 0
	var candidate *openapi.Appliance
	for _, c := range data {
		if util.InSlice(strings.ToLower(hostname), c.Hostnames) {
			count++
			candidate = &c.Appliance
			break
		}
	}
	if count > 1 {
		return nil, fmt.Errorf(
			"The given Controller hostname %s is used by more than one appliance."+
				"A unique Controller admin (or peer) hostname is required to perform the upgrade.",
			hostname,
		)
	}
	if candidate != nil {
		return candidate, nil
	}
	return nil, fmt.Errorf(
		"Unable to match the given Controller hostname %q with the actual Controller admin (or peer) hostname",
		hostname,
	)
}

func FindCurrentController(appliances []openapi.Appliance, hostname string) (*openapi.Appliance, error) {
	for _, a := range appliances {
		if a.GetHostname() == hostname {
			return &a, nil
		}
	}
	return nil, errors.New("No host controller found")
}

// AutoscalingGateways return the template appliance and all gateways
func AutoscalingGateways(appliances []openapi.Appliance) (*openapi.Appliance, []openapi.Appliance) {
	autoscalePrefix := "Autoscaling Instance"
	var template *openapi.Appliance
	r := make([]openapi.Appliance, 0)
	for _, a := range appliances {
		if util.InSlice("template", a.GetTags()) && !a.GetActivated() {
			template = &a
		}
		if v, ok := a.GetGatewayOk(); ok && v.GetEnabled() && strings.HasPrefix(a.GetName(), autoscalePrefix) {
			r = append(r, a)
		}
	}
	return template, r
}

func FilterAppliances(appliances []openapi.Appliance, filter map[string]map[string]string) []openapi.Appliance {
	// apply normal filter
	if len(filter["filter"]) > 0 {
		appliances = applyApplianceFilter(appliances, filter["filter"])
	}

	// apply exclusion filter
	toExclude := applyApplianceFilter(appliances, filter["exclude"])
	for _, exa := range toExclude {
		eID := exa.GetId()
		for i, a := range appliances {
			if eID == a.GetId() {
				appliances = append(appliances[:i], appliances[i+1:]...)
			}
		}
	}

	return appliances
}

func applyApplianceFilter(appliances []openapi.Appliance, filter map[string]string) []openapi.Appliance {
	var filteredAppliances []openapi.Appliance
	var warnings []string

	appendUnique := func(app openapi.Appliance) {
		appID := app.GetId()
		inFiltered := []string{}
		for _, a := range filteredAppliances {
			inFiltered = append(inFiltered, a.GetId())
		}
		if !util.InSlice(appID, inFiltered) {
			filteredAppliances = append(filteredAppliances, app)
		}
	}

	for _, a := range appliances {
		for k, s := range filter {
			switch k {
			case "name":
				nameList := strings.Split(s, FilterDelimiter)
				for _, name := range nameList {
					regex := regexp.MustCompile(name)
					if regex.MatchString(a.GetName()) {
						appendUnique(a)
					}
				}
			case "id":
				ids := strings.Split(s, FilterDelimiter)
				for _, id := range ids {
					regex := regexp.MustCompile(id)
					if regex.MatchString(a.GetId()) {
						appendUnique(a)
					}
				}
			case "tags", "tag":
				tagSlice := strings.Split(s, FilterDelimiter)
				appTags := a.GetTags()
				for _, t := range tagSlice {
					regex := regexp.MustCompile(t)
					for _, at := range appTags {
						if regex.MatchString(at) {
							appendUnique(a)
						}
					}
				}
			case "version":
				vList := strings.Split(s, FilterDelimiter)
				for _, v := range vList {
					regex := regexp.MustCompile(v)
					version := a.GetVersion()
					versionString := fmt.Sprintf("%d", version)
					if regex.MatchString(versionString) {
						appendUnique(a)
					}
				}
			case "hostname", "host":
				hostList := strings.Split(s, FilterDelimiter)
				for _, host := range hostList {
					regex := regexp.MustCompile(host)
					if regex.MatchString(a.GetHostname()) {
						appendUnique(a)
					}
				}
			case "active", "activated":
				b, err := strconv.ParseBool(s)
				if err != nil {
					message := fmt.Sprintf("Failed to parse boolean filter value: %x", err)
					if !util.InSlice(message, warnings) {
						warnings = append(warnings, message)
					}
				}
				if a.GetActivated() == b {
					appendUnique(a)
				}
			case "site", "site-id":
				siteList := strings.Split(s, FilterDelimiter)
				for _, site := range siteList {
					regex := regexp.MustCompile(site)
					if regex.MatchString(a.GetSite()) {
						appendUnique(a)
					}
				}
			case "function":
				functionList := strings.Split(s, FilterDelimiter)
				for _, function := range functionList {
					if functions := GetActiveFunctions(a); util.InSlice(function, functions) {
						appendUnique(a)
					}
				}
			default:
				message := fmt.Sprintf("'%s' is not a filterable keyword. Ignoring.", k)
				if !util.InSlice(message, warnings) {
					warnings = append(warnings, message)
				}
			}
		}
	}

	if len(warnings) > 0 {
		for _, warn := range warnings {
			logrus.Warnf(warn)
		}
	}

	return filteredAppliances
}

func GetVersion(s string) (*version.Version, error) {
	regex := regexp.MustCompile(`\d+\.\d+\.\d+([-|\+]?\d+)?`)
	match := regex.FindString(s)
	vString := strings.ReplaceAll(match, "-", "+")
	return version.NewVersion(vString)
}

func ShouldDisable(from, to *version.Version) bool {
	compare, _ := version.NewVersion("5.4")

	if from.LessThan(compare) {
		majorChange := from.Segments()[0] < to.Segments()[0]
		minorChange := from.Segments()[1] < to.Segments()[1]
		return majorChange || minorChange
	}

	return false
}
