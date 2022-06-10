package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/safestack-hq/labval/pkg/scm"
)

type ConfXml struct {
	XMLName   xml.Name     `xml:"configuration"`
	SystemWeb SystemWebXml `xml:"system.web"`
}

type SystemWebXml struct {
	XMLName     xml.Name       `xml:"system.web"`
	HttpCookies HttpCookiesXml `xml:"httpCookies"`
}

type HttpCookiesXml struct {
	XMLName    xml.Name `xml:"httpCookies"`
	RequireSSL string   `xml:"requireSSL,attr"`
}

type ValJson struct {
	RequireSSL string `json:"requiressl"`
}

type WebConfigEasy struct {
	*GlobalCmdOptions
	flagXmlFile string
}

func (w *WebConfigEasy) Help() string {
	helpText := `
Usage: labs-validator webconfig-easy -xml=<file>

`

	return strings.TrimSpace(helpText)
}

func (w *WebConfigEasy) Synopsis() string {
	return "Handle a trivial web.config file"
}

func (w *WebConfigEasy) Run(args []string) int {
	flagSet := w.GetFlagset("trivy")
	flagSet.StringVar(&w.flagXmlFile, "xml", "", "Input web.config XML file")
	flagSet.Parse(args)

	if w.flagXmlFile == "" {
		fmt.Printf("Error: missing -xml file\n")
		return 1
	}

	rawData, err := os.ReadFile(w.flagXmlFile)
	if err != nil {
		fmt.Printf("Error: issue reading file - '%s'\n", err)
		return 1
	}

	authToken := os.Getenv(LABS_AUTH)
	if authToken == "" {
		fmt.Printf("Error: Missing environment variable %s\n", LABS_AUTH)
		return 1
	}

	w.debugLog("Found LABS_AUTH")

	gh, err := scm.NewScm(authToken, w.flagDebug)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	err = gh.GetUrlFromClaims()
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	conf := ConfXml{}
	err = xml.Unmarshal(rawData, &conf)
	if err != nil {
		fmt.Printf("Error: Unmarshaling XML - '%s'\n", err)
		return 1
	}

	if w.flagDebug {
		spew.Dump(conf)
	}

	if conf.SystemWeb.HttpCookies.RequireSSL == "" {
		w.debugLog("No value found for RequireSSL")
	} else {
		w.debugLog(fmt.Sprintf("Found a value for the RequireSSL string: %s", conf.SystemWeb.HttpCookies.RequireSSL))
	}

	valJson := ValJson{
		RequireSSL: conf.SystemWeb.HttpCookies.RequireSSL,
	}

	prettyJson, err := json.Marshal(valJson)
	if err != nil {
		fmt.Printf("Error: can't parse back into json - '%s'\n", err)
		return 1
	}

	parsedResults, err := gh.SendData(prettyJson)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	if parsedResults.Error != "" {
		fmt.Printf("There was an error validating your config\n")
		fmt.Printf("Error message: '%s'\n", parsedResults.Error)
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
