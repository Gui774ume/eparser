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
	Use: "eparser",
}

var prog = &cobra.Command{
	Use:   "prog",
	Short: "prints information about one or multiple programs",
	Long:  "prints information about one or multiple programs from the provided ELF file",
	RunE:  progCmd,
}

var m = &cobra.Command{
	Use:   "map",
	Short: "prints information about one or multiple maps",
	Long:  "prints information about one or multiple maps from the provided ELF file",
	RunE:  mapCmd,
}

var report = &cobra.Command{
	Use:   "report",
	Short: "prints summarized information about the maps and programs",
	Long:  "prints summarized information about the maps and programs in the provided ELF file",
	RunE:  reportCmd,
}

var graph = &cobra.Command{
	Use:   "graph",
	Short: "graph plots programs and maps",
	Long:  "graph plots programs and maps in the provided ELF file",
	RunE:  graphCmd,
}

type EParserOptions struct {
	EBPFAssetPath string
	Section       string
	Helper        string
	Map           string
	Dump          bool
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

	prog.Flags().StringVar(
		&options.Section,
		"section",
		"",
		"program section selector")
	prog.Flags().StringVar(
		&options.Helper,
		"helper",
		"",
		"program section eBPF helper selector")
	prog.Flags().StringVar(
		&options.Map,
		"map",
		"",
		"map section selector")
	prog.Flags().BoolVar(
		&options.Dump,
		"dump",
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
	EParser.AddCommand(report)
	EParser.AddCommand(graph)
}
