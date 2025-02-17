package cmd

import (
	"os"

	"github.com/appgate/sdpctl/pkg/docs"
	"github.com/spf13/cobra"
)

// NewCmdCompletion represents the completion command
func NewCmdCompletion() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use: "completion [bash|zsh|fish|powershell]",
		Annotations: map[string]string{
			"skipAuthCheck": "true",
		},
		Short:     docs.CompletionDocs.Short,
		Long:      docs.CompletionDocs.Long,
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.ExactValidArgs(1),
		Example:   docs.CompletionDocs.ExampleString(),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}

	return completionCmd
}
