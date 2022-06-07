package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/safestack-hq/labs-validator/version"

	"github.com/mitchellh/cli"
)

func Run(args []string) int {

	globalCmdOptions := &GlobalCmdOptions{}

	Commands := map[string]cli.CommandFactory{
		"trivy": func() (cli.Command, error) {
			return &TrivyCommand{
				GlobalCmdOptions: globalCmdOptions,
			}, nil
		},
	}

	cli := &cli.CLI{
		Name:     "labs-validator",
		Version:  version.GetVersion(),
		Args:     args,
		Commands: Commands,
	}

	exitCode, err := cli.Run()

	if err != nil {
		fmt.Printf("Error running cli: '%s'\n", err)
		return 1
	}

	return exitCode
}

type GlobalCmdOptions struct {
	flagDebug bool
}

func (g *GlobalCmdOptions) GetFlagset(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ExitOnError)
	flagSet.BoolVar(&g.flagDebug, "debug", false, "Enable debug output")
	if os.Getenv("DEBUG") == "TRUE" {
		g.flagDebug = true
	}
	return flagSet
}

func (g *GlobalCmdOptions) debugLog(msg string) {
	if g.flagDebug {
		log.SetPrefix("labs-validator: ")
		log.SetFlags(log.Lshortfile | log.LstdFlags)
		log.Println(msg)
	}
}