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
	"github.com/Gui774ume/eparser/pkg/eparser"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func progCmd(cmd *cobra.Command, args []string) error {
	eparser, err := eparser.NewEParser(options.EBPFAssetsPath)
	if err != nil {
		logrus.Fatalf("failed to run EParser: %v", err)
	}
	if err := eparser.ShowProgram(options.Section, options.Dump); err != nil {
		logrus.Fatalf("failed to run EParser: %v", err)
	}
	return nil
}

func mapCmd(cmd *cobra.Command, args []string) error {
	eparser, err := eparser.NewEParser(options.EBPFAssetsPath)
	if err != nil {
		logrus.Fatalf("failed to run EParser: %v", err)
	}
	if err := eparser.ShowMap(options.Section); err != nil {
		logrus.Fatalf("failed to run EParser: %v", err)
	}
	return nil
}
