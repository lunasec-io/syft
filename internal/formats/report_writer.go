package formats

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

// behave like sbom.Writer
type writer struct {
	Format *format.Format
	io.Writer
	io.Closer
}

// Write the provided SBOM to all writers
func (o *writer) Write(s sbom.SBOM) (errs error) {
	return o.Format.Encode(o.Writer, s)
}

type SBOMWriter struct {
	Writers []sbom.Writer
	SBOM    sbom.SBOM
}

// Write writes the SBOM to all writers
func (s *SBOMWriter) Write() (errs error) {
	for _, w := range s.Writers {
		err := w.Write(s.SBOM)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// Close any resources, such as open files
func (o *SBOMWriter) Close() (errs error) {
	for _, w := range o.Writers {
		if c, ok := w.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = multierror.Append(errs, err)
			}
		}
	}
	return errs
}

// ParseOptions utility to parse command-line option strings consistently while applying
// the provided default format and file
func ParseOptions(options []string, format format.Option, file string) (out []WriterOption) {
	if len(options) > 0 {
		for _, option := range options {
			option = strings.TrimSpace(option)
			if strings.Contains(option, "=") {
				parts := strings.SplitN(option, "=", 2)
				out = append(out, WriterOption{
					format: parts[0],
					path:   parts[1],
				})
			} else {
				out = append(out, WriterOption{
					format: option,
					path:   strings.TrimSpace(file),
				})
			}
		}
	} else {
		out = append(out, WriterOption{
			format: string(format),
			path:   strings.TrimSpace(file),
		})
	}
	return out
}

type WriterOption struct {
	format string
	path   string
}

// MakeWriters create all report writers from input options, accepts options of the form:
// <format> --or-- <format>=<file>
func MakeWriters(options []WriterOption) ([]sbom.Writer, func() error, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	var out []sbom.Writer

	for _, option := range options {
		// set the presenter
		formatOption := format.ParseOption(option.format)
		if formatOption == format.UnknownFormatOption {
			return nil, fmt.Errorf("bad --output value '%s'", option)
		}

		outputFormat := ByOption(formatOption)
		if outputFormat == nil {
			return nil, fmt.Errorf("unknown format: %s", option)
		}

		switch len(option.path) {
		case 0:
			out = append(out, &writer{
				Format: outputFormat,
				Writer: os.Stdout,
				Closer: io.NopCloser(os.Stdout),
			})
		default:
			fileOut, err := fileOutput(option.path)
			if err != nil {
				return nil, err
			}
			out = append(out, &writer{
				Format: outputFormat,
				Writer: fileOut,
				Closer: fileOut,
			})
		}
	}

	c := func() error {
		var errs error
		for _, w := range out {
			if c, ok := w.(io.Closer); ok {
				if err := c.Close(); err != nil {
					errs = multierror.Append(errs, err)
				}
			}
		}
		return errs
	}

	return out, c, nil
}

func fileOutput(path string) (*os.File, error) {
	reportFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	if err != nil {
		return nil, fmt.Errorf("unable to create report file: %w", err)
	}

	return reportFile, nil
}
