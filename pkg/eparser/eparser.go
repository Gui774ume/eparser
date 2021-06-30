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

package eparser

import (
	"fmt"
	"os"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/asm"
	"github.com/pkg/errors"
)

// EParser is the main EParser structure
type EParser struct {
	collectionSpec *ebpf.CollectionSpec
}

func (e *EParser) parseAsset(asset string) error {
	if _, err := os.Stat(asset); err != nil {
		return err
	}

	f, err := os.Open(asset)
	if err != nil {
		return err
	}

	e.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return err
	}
	return nil
}

// NewEParser returns a new EParser instance
func NewEParser(asset string) (*EParser, error) {
	e := &EParser{}

	// parse asset
	if err := e.parseAsset(asset); err != nil {
		return nil, errors.Wrapf(err, "couldn't parse asset %s", asset)
	}
	return e, nil
}

// ShowProgram prints information about the provided program section. If no section is provided, all the programs will
// be displayed.
func (e *EParser) ShowProgram(section string, dumpByteCode bool) error {
	// if a program section is provided, dump program info
	if len(section) != 0 {
		spec, ok := e.collectionSpec.Programs[section]
		if !ok {
			return errors.Errorf("%s section not found in %s", section, section)
		}
		e.printProgramSpec(spec, dumpByteCode)
		return nil
	}

	// if not, dump all programs
	for _, spec := range e.collectionSpec.Programs {
		e.printProgramSpec(spec, dumpByteCode)
	}
	return nil
}

func (e *EParser) printProgramSpec(spec *ebpf.ProgramSpec, dumpByteCode bool) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", spec.SectionName)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  InstructionsCount: %d\n", len(spec.Instructions))
	fmt.Printf("  AttachType: %d\n", spec.AttachType)
	fmt.Printf("  License: %s\n", spec.License)
	fmt.Printf("  KernelVersion: %d\n", spec.KernelVersion)
	fmt.Printf("  ByteOrder: %s\n", spec.ByteOrder)

	helpers := map[asm.BuiltinFunc]int{}
	maps := map[string]int{}
	for _, ins := range spec.Instructions {
		if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall {
			helpers[asm.BuiltinFunc(ins.Constant)] += 1
		}
		if len(ins.Reference) > 0 {
			maps[ins.Reference] += 1
		}
	}

	// Print list of eBPF helpers
	if len(helpers) > 0 {
		fmt.Println("  Helpers:")
	}
	for helper, count := range helpers {
		fmt.Printf("    - %s: %d\n", helper, count)
	}

	// Print list of maps
	if len(maps) > 0 {
		fmt.Println("  Maps:")
	}
	for m, count := range maps {
		fmt.Printf("    - %s: %d\n", m, count)
	}

	if dumpByteCode {
		fmt.Printf("  Bytecode:\n%s", spec.Instructions[1:])
	}
	fmt.Println()
}

// ShowMap prints information about the provided map section. If no section is provided, all the maps will
// be displayed.
func (e *EParser) ShowMap(section string) error {
	// if a map section is provided, dump map info
	if len(section) != 0 {
		spec, ok := e.collectionSpec.Maps[section]
		if !ok {
			return errors.Errorf("%s section not found in %s", section, section)
		}
		e.printMapSpec(spec, section)
		return nil
	}

	// if not, dump all maps
	for sec, spec := range e.collectionSpec.Maps {
		e.printMapSpec(spec, sec)
	}
	return nil
}

func (e *EParser) printMapSpec(spec *ebpf.MapSpec, section string) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", section)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  Flags: %d\n", spec.Flags)
	fmt.Printf("  KeySize: %d\n", spec.KeySize)
	fmt.Printf("  ValueSize: %d\n", spec.ValueSize)
	fmt.Printf("  MaxEntries: %d\n\n", spec.MaxEntries)
}

func (e *EParser) ShowReport() error {
	// Compute list of program types and eBPF helpers
	progTypes := map[ebpf.ProgramType]map[string]int{}
	helpers := map[asm.BuiltinFunc]map[string]int{}
	progMaps := map[string]map[string]int{}
	for _, p := range e.collectionSpec.Programs {
		if progTypes[p.Type] == nil {
			progTypes[p.Type] = map[string]int{}
		}
		progTypes[p.Type][p.SectionName] = 1
		for _, ins := range p.Instructions {
			if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall {
				helper := asm.BuiltinFunc(ins.Constant)
				if helpers[helper] == nil {
					helpers[helper] = map[string]int{}
				}
				helpers[helper][p.SectionName] += 1
			}
			if len(ins.Reference) > 0 {
				if progMaps[ins.Reference] == nil {
					progMaps[ins.Reference] = map[string]int{}
				}
				progMaps[ins.Reference][p.SectionName] += 1
			}
		}
	}

	// Compute list of map types
	mapTypes := map[ebpf.MapType]map[string]int{}
	for _, m := range e.collectionSpec.Maps {
		if mapTypes[m.Type] == nil {
			mapTypes[m.Type] = map[string]int{}
		}
		mapTypes[m.Type][m.Name] = 1
	}

	fmt.Printf("Program types report (detected %d different types):\n", len(progTypes))
	for t, progs := range progTypes {
		fmt.Printf("  - %s:\n", t)
		for p := range progs {
			fmt.Printf("    * %s\n", p)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("eBPF helpers report (detected %d different helpers):\n", len(helpers))
	for helper, progs := range helpers {
		fmt.Printf("  - %s:\n", helper)
		for p, count := range progs {
			fmt.Printf("    * %s: %d\n", p, count)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("Map types report (detected %d different types):\n", len(mapTypes))
	for t, maps := range mapTypes {
		fmt.Printf("  - %s:\n", t)
		for m := range maps {
			fmt.Printf("    * %s\n", m)
			for p, count := range progMaps[m] {
				fmt.Printf("      + %s: %d\n", p, count)
			}
		}
	}
	return nil
}
