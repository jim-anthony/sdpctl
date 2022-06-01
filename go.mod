module github.com/appgate/sdpctl

go 1.16

require (
	github.com/AlecAivazis/survey/v2 v2.3.4
	github.com/appgate/sdp-api-client-go v1.0.7-0.20220601133351-40ed07b2b855
	github.com/billgraziano/dpapi v0.4.0
	github.com/cenkalti/backoff/v4 v4.1.3
	github.com/cheynewallace/tabby v1.1.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/enriquebris/goconcurrentqueue v0.6.3
	github.com/google/go-cmp v0.5.8
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.4.0
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.11.0
	github.com/stretchr/testify v1.7.1
	github.com/vbauerster/mpb/v7 v7.4.1
	github.com/zalando/go-keyring v0.2.1
	golang.org/x/net v0.0.0-20220531201128-c960675eff93 // indirect
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

replace github.com/appgate/sdp-api-client-go => /home/daniel/dev/sdp-api-client-go
