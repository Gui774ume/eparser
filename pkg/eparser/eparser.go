package eparser

import (
	"fmt"
	"os"

	"github.com/DataDog/ebpf"
	"github.com/pkg/errors"
)

// EParser is the main EParser structure
type EParser struct {
	collectionSpec *ebpf.CollectionSpec
}

func (e *EParser) parseAssets(assets string) error {
	if _, err := os.Stat(assets); err != nil {
		return err
	}

	f, err := os.Open(assets)
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
func NewEParser(assets string) (*EParser, error) {
	e := &EParser{}

	// parse assets
	if err := e.parseAssets(assets); err != nil {
		return nil, errors.Wrap(err, "couldn't parse assets")
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