/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package run

import (
	"github.com/spf13/cobra"
)

// EParser represents the base command of eparser
var EParser = &cobra.Command{
	Use:   "eparser",
}

var prog = &cobra.Command{
	Use: "prog",
	Short: "prints information about one or multiple programs",
	Long: "prints information about one or multiple programs from the provided ELF file",
	RunE: progCmd,
}

var m = &cobra.Command{
	Use: "map",
	Short: "prints information about one or multiple maps",
	Long: "prints information about one or multiple maps from the provided ELF file",
	RunE: mapCmd,
}

type EParserOptions struct {
	EBPFAssetPath string
	Section        string
	Dump           bool
}

var options EParserOptions

func init() {
	EParser.PersistentFlags().StringVarP(
		&options.EBPFAssetPath,
		"asset",
		"a",
		"",
		"path to the eBPF asset (ELF format expected)")
	_ = EParser.MarkPersistentFlagRequired("asset")

	prog.Flags().StringVarP(
		&options.Section,
		"section",
		"s",
		"",
		"program section to dump")
	prog.Flags().BoolVarP(
		&options.Dump,
		"dump",
		"d",
		false,
		"dump the program bytecode")

	m.Flags().StringVarP(
		&options.Section,
		"section",
		"s",
		"",
		"map section to dump")

	EParser.AddCommand(prog)
	EParser.AddCommand(m)
}
