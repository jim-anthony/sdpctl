package httpmock

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"testing/fstest"

	"github.com/appgate/appgatectl/pkg/util"
	"github.com/appgate/sdp-api-client-go/api/v16/openapi"
	"github.com/google/go-cmp/cmp"
)

var TransformJSONFilter = cmp.FilterValues(func(x, y []byte) bool {
	// https://github.com/google/go-cmp/issues/224#issuecomment-650429859
	return json.Valid(x) && json.Valid(y)
}, cmp.Transformer("ParseJSON", func(in []byte) (out interface{}) {
	if err := json.Unmarshal(in, &out); err != nil {
		panic(err) // should never occur given previous filter to ensure valid JSON
	}
	return out
}))

type Registry struct {
	Client   *openapi.APIClient
	cfg      *openapi.Configuration
	Mux      *http.ServeMux
	server   *httptest.Server
	Port     int
	Teardown func()
	Requests []*http.Request
	stubs    []*Stub
}

func NewRegistry() *Registry {
	client, cfg, mux, srv, port, teardown := setup()

	r := &Registry{
		Client:   client,
		cfg:      cfg,
		Mux:      mux,
		server:   srv,
		Port:     port,
		Teardown: teardown,
	}
	os.Setenv("APPGATECTL_BEARER", "header-token-value")
	return r
}

type Stub struct {
	URL       string
	Responder http.HandlerFunc
}

func (r *Registry) Register(url string, resp http.HandlerFunc) {
	r.stubs = append(r.stubs, &Stub{
		URL:       url,
		Responder: resp,
	})
}

func (r *Registry) Serve() {
	for _, stub := range r.stubs {
		r.Mux.HandleFunc(stub.URL, stub.Responder)
	}
}

func setup() (*openapi.APIClient, *openapi.Configuration, *http.ServeMux, *httptest.Server, int, func()) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	clientCfg := openapi.NewConfiguration()

	// toggle this if you want to see response body in test
	if v, err := strconv.ParseBool(util.Getenv("DEBUG", "false")); v && err == nil {
		clientCfg.Debug = v
	}

	u, _ := url.Parse(server.URL)
	clientCfg.Servers = []openapi.ServerConfiguration{
		{
			URL: u.String(),
		},
	}

	c := openapi.NewAPIClient(clientCfg)

	port := server.Listener.Addr().(*net.TCPAddr).Port
	return c, clientCfg, mux, server, port, server.Close
}

func JSONResponse(filename string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filename)
		if err != nil {
			panic(fmt.Sprintf("Internal testing error: could not open %q", filename))
		}
		defer f.Close()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		reader := bufio.NewReader(f)
		content, err := io.ReadAll(reader)
		if err != nil {
			panic(fmt.Sprintf("Internal testing error: could not read %q", filename))
		}
		fmt.Fprint(rw, string(content))
	}
}

func FileResponse() http.HandlerFunc {
	filename := "test-file.txt"
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			rg := regexp.MustCompile("gpg$")
			accHeader := r.Header.Get("Accept")
			if !rg.MatchString(accHeader) {
				rw.WriteHeader(http.StatusNotAcceptable)
			}

			rw.WriteHeader(http.StatusNoContent)
		}

		if r.Method == http.MethodGet {
			fs := fstest.MapFS{
				filename: {
					Data: []byte("testfile"),
				},
			}
			f, _ := fs.Open(filename)
			rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", f))
			rw.Header().Set("Content-Type", "application/file")
			rw.WriteHeader(http.StatusOK)
			reader := bufio.NewReader(f)
			content, err := io.ReadAll(reader)
			if err != nil {
				panic(fmt.Sprintf("Internal testing error: could not read %q", filename))
			}
			fmt.Fprint(rw, string(content))
		}
	}
}
