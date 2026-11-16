package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/longicorn/ichnograph/internal/clew"
)

type clewValues []string

func (v *clewValues) String() string     { return fmt.Sprint([]string(*v)) }
func (v *clewValues) Set(s string) error { *v = append(*v, s); return nil }

func clewFlags(w io.Writer) (*flag.FlagSet, *string, *string) {
	f := flag.NewFlagSet("clew", flag.ContinueOnError)
	f.SetOutput(w)
	f.Var(new(clewValues), "include", "include records matching `predicate` (repeatable)")
	f.Var(new(clewValues), "exclude", "exclude records matching `predicate` (repeatable)")
	f.Var(new(clewValues), "tag", "add a tag for matching records using `tag:predicate` (repeatable)")
	f.Bool("tag-file-type", false, "tag detected file types")
	group := f.String("group-by", "pid,tid", "grouping keys (only pid,tid is supported)")
	output := f.String("o", "-", "output JSON file (- for stdout)")
	f.Usage = func() {
		fmt.Fprintln(w, "usage: ichnograph clew [-group-by pid,tid] [-include predicate] [-exclude predicate] [-tag rule] [-tag-file-type] [-o output.json] [input.json]\nGroup trace or clew JSON output; input defaults to stdin.\nOptions:")
		f.PrintDefaults()
		fmt.Fprintln(w, `
Predicates:
  field=value    Exact match for a string, number, or boolean.
  field~=value   Substring match for a string (not a regular expression).
  Fields and tags start with an ASCII letter or underscore and contain only
  ASCII letters, digits, and underscores. Values must not be empty.
  Missing fields and incompatible types do not match.

  Include predicates are combined with OR; any matching exclude removes the
  record. Without include predicates, all records are included initially.
  Tags are appended to the record's tags array without duplicates. File type
  detection reads local files, preferring resolved_path over path.

Examples:
  ichnograph clew -include 'success=true' trace.json
  ichnograph clew -exclude 'path~=/tmp/' trace.json
  ichnograph clew -tag 'gem:path~=/gem/ruby/' trace.json
  ichnograph clew -tag-file-type trace.json`)

	}
	return f, group, output
}

func runClew(args []string) int {
	f, group, output := clewFlags(os.Stderr)
	include := f.Lookup("include").Value.(*clewValues)
	exclude := f.Lookup("exclude").Value.(*clewValues)
	tags := f.Lookup("tag").Value.(*clewValues)
	fileType := f.Lookup("tag-file-type").Value.(flag.Getter)

	f.Usage = func() {}
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			printHelp(os.Stdout, "clew")
			return 0
		}
		printHelp(os.Stderr, "clew")
		return 2
	}
	if *group != "pid,tid" || f.NArg() > 1 {
		return usageError("invalid grouping keys or unexpected arguments", "clew")
	}
	var opts clew.Options
	for _, s := range *include {
		p, err := clew.ParsePredicate(s)
		if err != nil {
			return usageError(err.Error(), "clew")
		}
		opts.Include = append(opts.Include, p)
	}
	for _, s := range *exclude {
		p, err := clew.ParsePredicate(s)
		if err != nil {
			return usageError(err.Error(), "clew")
		}
		opts.Exclude = append(opts.Exclude, p)
	}
	for _, s := range *tags {
		p, err := clew.ParseRule(s)
		if err != nil {
			return usageError(err.Error(), "clew")
		}
		opts.Tags = append(opts.Tags, p)
	}
	if fileType.Get().(bool) {
		opts.Detector = clew.FileDetector{}
	}
	input := "-"
	if f.NArg() == 1 {
		input = f.Arg(0)
	}
	var data []byte
	var err error
	if input == "-" {
		data, err = os.ReadFile("/dev/stdin")
	} else {
		data, err = os.ReadFile(input)
	}
	if err == nil {
		data, err = clew.Process(data, opts)
	}
	if err == nil {
		if *output == "-" {
			_, err = os.Stdout.Write(data)
		} else {
			err = os.WriteFile(*output, data, 0644)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
