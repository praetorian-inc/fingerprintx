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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type outputFormat string

const (
	JSON    outputFormat = "JSON"
	CSV     outputFormat = "CSV"
	DEFAULT outputFormat = "DEFAULT"
)

type dataEntry struct {
	Host      string         `json:"host,omitempty"`
	IP        string         `json:"ip"`
	Port      uint16         `json:"port"`
	Service   string         `json:"service"`
	Transport string         `json:"transport"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Error     string         `json:"error,omitempty"`
}

func Report(results []scan.ReportedResult) error {
	var writeFile *os.File
	var outputFormat = DEFAULT
	var csvWriter *csv.Writer
	var err error

	log.SetFlags(0)

	if len(config.outputFile) > 0 {
		var fileErr error
		writeFile, fileErr = os.Create(config.outputFile)
		if fileErr != nil {
			return fileErr
		}
		log.SetOutput(writeFile)
	} else {
		log.SetOutput(os.Stdout)
	}
	defer writeFile.Close()

	if config.outputJSON {
		outputFormat = JSON
	} else if config.outputCSV {
		outputFormat = CSV
		csvWriter = csv.NewWriter(writeFile)
		if config.showErrors {
			err = csvWriter.Write([]string{"Host", "Port", "Service", "Metadata", "Error"})
		} else {
			err = csvWriter.Write([]string{"Host", "Port", "Service", "Data"})
		}
		if err != nil {
			return err
		}
	}

	for _, result := range results {
		if (result.Results == nil) == (result.Error == nil) {
			panic("PluginResults must have non-nil value for either Results or Error field")
		}

		host := hostMapping[result.Addr]
		data := dataEntry{
			Host:      host,
			Port:      result.Addr.Port(),
			IP:        result.Addr.Addr().String(),
			Service:   result.Plugin.Name(),
			Transport: strings.ToLower(result.Plugin.Type().String()),
		}
		if result.Results != nil {
			data.Metadata = result.Results.Info
		}
		if config.showErrors && result.Error != nil {
			data.Error = result.Error.Error()
			if data.Error == "" {
				data.Error = "Unknown error occurred with no error message."
			}
		}

		displayedHost := data.IP
		if data.Host != "" {
			displayedHost = data.Host
		}

		switch outputFormat {
		case JSON:
			if data.Error == "" || (data.Error != "" && config.showErrors) {
				var jsonErr error
				jsonData, jsonErr := json.Marshal(data)
				if jsonErr != nil {
					return jsonErr
				}
				log.Println(string(jsonData))
			}
		case CSV:
			portStr := strconv.FormatInt(int64(data.Port), 10)
			if config.showErrors {
				if data.Error != "" {
					err = csvWriter.Write(
						[]string{data.Host, portStr, data.Service, "", data.Error},
					)
				} else {
					err = csvWriter.Write([]string{displayedHost, portStr, data.Service, fmt.Sprint(data.Metadata), ""})
				}
			} else {
				if data.Error == "" {
					err = csvWriter.Write([]string{displayedHost, portStr, data.Service, fmt.Sprint(data.Metadata)})
				}
			}
			if err != nil {
				return err
			}
			csvWriter.Flush()
		default:
			if data.Error != "" {
				if config.showErrors {
					log.Printf(
						"[ERROR]: Scanning %s:%d for %s: %s\n",
						displayedHost,
						data.Port,
						strings.ToLower(data.Service),
						data.Error,
					)
				}
			} else {
				log.Printf("%s://%s:%d\n", strings.ToLower(data.Service), displayedHost, data.Port)
			}
		}
	}
	return nil
}
