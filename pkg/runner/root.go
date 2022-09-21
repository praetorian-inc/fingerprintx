package runner

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/praetorian-inc/fingerprintx/pkg/scan"
	"github.com/spf13/cobra"
)

var (
	config      cliConfig
	hostMapping map[netip.AddrPort]string
	targetList  []string
	userInput   string
	rootCmd     = &cobra.Command{
		Use:   "./fingerprintx [flags]",
		Short: "A utility for service fingerprinting",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			configErr := checkConfig(config)
			if configErr != nil {
				return configErr
			}

			hostMapping = make(map[netip.AddrPort]string)
			targetsList, err := readTargets(inputFile)
			if err != nil {
				return err
			}

			results, err := scan.ScanTargets(targetsList, createScanConfig(config))
			if err != nil {
				return fmt.Errorf("Failed running ScanTargets (%w)", err)
			}

			err = Report(results)
			if err != nil {
				return fmt.Errorf("Failed reporting results (%w)", err)
			}

			return nil
		},
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	rootCmd.PersistentFlags().StringVarP(&inputFile, "list", "l", "", "input file containing targets")
	rootCmd.PersistentFlags().StringSliceVarP(&targetList, "targets", "t", nil, "target or comma separated target list")
	rootCmd.PersistentFlags().StringVarP(&config.outputFile, "output", "o", "", "output file")
	rootCmd.PersistentFlags().
		BoolVarP(&config.outputJSON, "json", "", false, "output format in json")
	rootCmd.PersistentFlags().BoolVarP(&config.outputCSV, "csv", "", false, "output format in csv")

	rootCmd.PersistentFlags().BoolVarP(&config.fastMode, "fast", "f", false, "fastlane mode")
	rootCmd.PersistentFlags().
		BoolVarP(&config.useUDP, "udp", "U", false, "run UDP plugins")

	rootCmd.PersistentFlags().BoolVarP(&config.verbose, "verbose", "v", false, "verbose mode")
	rootCmd.PersistentFlags().
		IntVarP(&config.timeout, "timeout", "w", 500, "timeout (milliseconds)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
