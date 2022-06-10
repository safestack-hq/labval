package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/safestack-hq/labval/pkg/scm"

	"github.com/olekukonko/tablewriter"
)

// Trivy's JSON output
type TJson struct {
	SchemaVersion float64   `json:"SchemaVersion"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Results       []TResult `json:"Results"`
}

// Trivy JSON Results
type TResult struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Summary           map[string]float64 `json:"MisconfSummary"`
	Misconfigurations []TMisconfigs      `json:"Misconfigurations"`
}

// Trivy JSON misconfigurations
type TMisconfigs struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Message     string `json:"Message"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"`
	PrimaryURL  string `json:"PrimaryURL"`
	Resolution  string `json:"Resolution"`
}

// The trivy sub-command for labval
type TrivyCommand struct {
	*GlobalCmdOptions
	flagJsonFile string
}

func (t *TrivyCommand) Help() string {
	helpText := `
Usage: labs-validator trivy -json=<file>

`

	return strings.TrimSpace(helpText)
}

func (t *TrivyCommand) Synopsis() string {
	return "Handle trivy output"
}

func (t *TrivyCommand) Run(args []string) int {
	flagSet := t.GetFlagset("trivy")
	flagSet.StringVar(&t.flagJsonFile, "json", "", "Input JSON file")
	flagSet.Parse(args)

	if t.flagJsonFile == "" {
		fmt.Printf("Error: missing -json file\n")
		return 1
	}

	rawData, err := os.ReadFile(t.flagJsonFile)
	if err != nil {
		fmt.Printf("Error: issue reading file - '%s'\n", err)
		return 1
	}

	authToken := os.Getenv(LABS_AUTH)
	if authToken == "" {
		fmt.Printf("Error: Missing environment variable %s\n", LABS_AUTH)
		return 1
	}

	t.debugLog("Found LABS_AUTH")

	gh, err := scm.NewScm(authToken, t.flagDebug)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	err = gh.GetUrlFromClaims()
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	var parsedJson TJson
	json.Unmarshal(rawData, &parsedJson)

	if parsedJson.Results == nil {
		t.debugLog("No results found")
	} else {
		t.debugLog(fmt.Sprintf("We found %d results, this is good", len(parsedJson.Results)))

		s := "na"
		f := "na"
		e := "na"

		if sRaw, exists := parsedJson.Results[0].Summary["Successes"]; exists {
			s = fmt.Sprintf("%d", int(sRaw))
		}

		if fRaw, exists := parsedJson.Results[0].Summary["Failures"]; exists {
			f = fmt.Sprintf("%d", int(fRaw))
		}

		if eRaw, exists := parsedJson.Results[0].Summary["Exceptions"]; exists {
			e = fmt.Sprintf("%d", int(eRaw))
		}

		t.debugLog(fmt.Sprintf("Successes: %s - Failures: %s - Exceptions: %s", s, f, e))

		if parsedJson.Results[0].Misconfigurations == nil {
			t.debugLog("No misconfigurations found")
		} else {
			t.debugLog("Found misconfigs:")

			for _, mc := range parsedJson.Results[0].Misconfigurations {
				t.debugLog(fmt.Sprintf("Type: %s", mc.Type))
				t.debugLog(fmt.Sprintf("ID: %s", mc.ID))
				t.debugLog(fmt.Sprintf("Title: %s", mc.Title))
				t.debugLog(fmt.Sprintf("URL: %s", mc.PrimaryURL))
				t.debugLog(fmt.Sprintf("Message: %s", mc.Message))
			}
		}
	}

	prettyJson, err := json.Marshal(parsedJson)
	if err != nil {
		fmt.Printf("Error: can't parse back into json - '%s'\n", err)
		return 1
	}

	t.debugLog(fmt.Sprintf("Final json: %s", string(prettyJson)))

	// Send our results back to the labval backend
	parsedResults, err := gh.SendData(prettyJson)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	// There were some errors with the scanners findings
	if parsedResults.Error != "" {
		fmt.Printf("There was an error validating your scanner results\n")
		fmt.Printf("Error message: '%s'\n", parsedResults.Error)

		// We have findings, let's pretty print them out to the console
		if parsedResults.Findings != nil {
			fmt.Printf("\nOutstanding Findings:\n")

			fTable := [][]string{}

			for _, finding := range parsedResults.Findings {
				fRow := []string{finding.Type, finding.ID, finding.Title, finding.Severity}
				fTable = append(fTable, fRow)
				fRow = []string{finding.Type, finding.ID, finding.Description, finding.Severity}
				fTable = append(fTable, fRow)
				fRow = []string{finding.Type, finding.ID, finding.Message, finding.Severity}
				fTable = append(fTable, fRow)
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Type", "ID", "Finding", "Severity"})
			table.SetAutoMergeCells(true)
			table.SetRowLine(true)
			table.AppendBulk(fTable)
			table.Render()

		}
		return 1
	}

	// This indicates everything has passed successfully
	if parsedResults.Result != "" {
		retString, err := gh.GetValUrlFromClaims(parsedResults.Result)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		fmt.Printf(retString)
	}

	return 0
}
