package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "seacrypt",
	Short: "seacrypt is a tool that enables us to decrypt base64 encoded secrets with aws kms",
	Long:  `seacrypt is a tool that enables us to decrypt base64 encoded secrets with aws kms`,
}

// execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
