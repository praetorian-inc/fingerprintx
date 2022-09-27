// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	rootCmd.PersistentFlags().BoolVarP(&config.fastMode, "fast", "f", false, "fast mode")
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
