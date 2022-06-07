package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt"
	"github.com/olekukonko/tablewriter"
)

const pubpem = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cjxlhAMct2J6OJfTf6s
cPZGf7wmeJ+LvNsj3G1irZpKFPBn0C3GF74VOADYN2oipQWJo2i0hdyc6rRjMXUV
bUGDOwQKEsr+rLx7WC2L/Jea7s7POgiDLmI0jod47c1C3Ph2GGdQ+n7D2d2n2j9T
ENOMYdVFh3GzqqYXKmSb9C5R5hTjKT50WZGgHKJ8d0egBMveqGt8gVxMHEW48SWC
5CtHl6an7FayzIL96/YEbHRLoWHOlpxJOnHw+fZ17ONa7LpF/KmgM2Wpc4qG6PUV
ezweTW/yLdaLrKxZOj1SUJuQ3oM3FJLc48eQ8lSUy9nsDCdfM/ZDtk9eecX0G+SI
KQIDAQAB
-----END PUBLIC KEY-----`

type TJson struct {
	SchemaVersion float64   `json:"SchemaVersion"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Results       []TResult `json:"Results"`
}

type TResult struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Summary           map[string]float64 `json:"MisconfSummary"`
	Misconfigurations []TMisconfigs      `json:"Misconfigurations"`
}

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

type ApiJson struct {
	Auth string `json:"auth"`
	Data string `json:"data"`
}

type ApiJsonResFinding struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ApiJsonRes struct {
	Result   string              `json:"result"`
	Error    string              `json:"error"`
	Findings []ApiJsonResFinding `json:"findings"`
}

type ScmJwt struct {
	Lstate string `json:"Lstate"`
	Lcb    string `json:"Lcb"`
	jwt.StandardClaims
}

type ValJwt struct {
	Lstate string `json:"Lstate"`
	Lvurl  string `json:"Lvurl"`
	jwt.StandardClaims
}

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

	authToken := os.Getenv("LABS_AUTH")
	if authToken == "" {
		fmt.Printf("Error: Missing environment variable LABS_AUTH\n")
		return 1
	}

	t.debugLog("Found LABS_AUTH")

	// Let's try and validate and get claims out of this token
	block, _ := pem.Decode([]byte(pubpem))
	if block == nil {
		fmt.Printf("Error: No pem\n")
		return 1
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error: Error parsing pem block - '%s'\n", err)
		return 1
	}

	t.debugLog("Got a successful rsa pub key:")
	if t.flagDebug {
		spew.Dump(pub)
	}

	claims := &ScmJwt{}

	tkn, err := jwt.ParseWithClaims(authToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	})
	if err != nil {
		fmt.Printf("Error: Parsing claims from jwt - '%s'\n", err)
		return 1
	}

	if !tkn.Valid {
		fmt.Printf("Error: invalid jwt\n")
		return 1
	}

	t.debugLog("Got claims")
	if t.flagDebug {
		spew.Dump(tkn)
		spew.Dump(claims)
	}

	url := ""
	if claims.Lstate == "scm_token" {
		url = claims.Lcb
	}

	if os.Getenv("LABS_ENV") == "local" {
		t.debugLog("Running against local test environment")
		url = "http://localhost/exercise/squirrel/scm_api_callback"
	} else if os.Getenv("LABS_ENV") == "dev" {
		t.debugLog("Running against dev environment")
		url = "http://labs-exercise-test-508391972.ap-southeast-2.elb.amazonaws.com/exercise/squirrel/scm_api_callback"
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

	b64 := base64.StdEncoding.EncodeToString(prettyJson)

	t.debugLog(fmt.Sprintf("Final b64: %s", b64))

	// Now we call out to the API

	client := http.Client{
		Timeout: time.Second * 30,
	}

	jsonBody := ApiJson{
		Auth: authToken,
		Data: b64,
	}

	body, err := json.Marshal(jsonBody)
	if err != nil {
		fmt.Printf("Error: Marshaling json - '%s'\n", err)
		return 1
	}

	t.debugLog(fmt.Sprintf("JSON MSG to be SENT TO LABS VALIDATOR: %s", jsonBody))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))

	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: Sending HTTP request - '%s'\n", err)
		return 1
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error: Reading HTTP response - '%s'\n", err)
		return 1
	}

	if t.flagDebug {
		fmt.Printf("Result body:\n")
		spew.Dump(resBody)
	}

	parsedResults := ApiJsonRes{}
	err = json.Unmarshal(resBody, &parsedResults)
	if err != nil {
		fmt.Printf("Error: parsing response json - '%s'\n", err)
		return 1
	}

	if t.flagDebug {
		fmt.Printf("Parsed results:\n")
		spew.Dump(parsedResults)
	}

	if parsedResults.Error != "" {
		fmt.Printf("There was an error validating your scanner results\n")
		fmt.Printf("Error message: '%s'\n", parsedResults.Error)
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

	if parsedResults.Result != "" {
		// Let's validate the JWT and get the claims out
		newclaims := &ValJwt{}
		tkn, err = jwt.ParseWithClaims(parsedResults.Result, newclaims, func(token *jwt.Token) (interface{}, error) {
			return pub, nil
		})
		if err != nil {
			fmt.Printf("Error: Parsing claims from jwt - '%s'\n", err)
			return 1
		}

		if !tkn.Valid {
			fmt.Printf("Error: invalid jwt\n")
			return 1
		}

		t.debugLog("Got claims")
		if t.flagDebug {
			spew.Dump(tkn)
			spew.Dump(newclaims)
		}

		validateUrl := ""
		if newclaims.Lstate == "validation_token" {
			validateUrl = newclaims.Lvurl
		}
		b64res := base64.URLEncoding.EncodeToString([]byte(parsedResults.Result))
		fmt.Printf("labs validation success!\nVisit %s?%s or visit %s and enter this token to continue:\n\n%s\n\n", validateUrl, b64res, validateUrl, b64res)
	}

	return 0
}
