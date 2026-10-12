// Package output renders scan results as a table, JSON or CSV.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/kelvinngeno/portscout/internal/scanner"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "csv"}

// Write renders results to w in the requested format.
func Write(w io.Writer, format string, results []scanner.Result) error {
	switch format {
	case "table":
		return writeTable(w, results)
	case "json":
		return writeJSON(w, results)
	case "csv":
		return writeCSV(w, results)
	default:
		return fmt.Errorf("unknown format %q (choose table, json or csv)", format)
	}
}

func writeTable(w io.Writer, results []scanner.Result) error {
	if len(results) == 0 {
		_, err := fmt.Fprintln(w, "No results.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSTATE\tSERVICE\tLATENCY\tBANNER")
	for _, r := range results {
		latency := "-"
		if r.LatencyMS > 0 {
			latency = fmt.Sprintf("%.1fms", r.LatencyMS)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n",
			r.Host, r.Port, r.State, r.Service, latency, r.Banner)
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, results []scanner.Result) error {
	if results == nil {
		results = []scanner.Result{} // emit [] rather than null
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeCSV(w io.Writer, results []scanner.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"host", "ip", "port", "state", "service", "latency_ms", "banner"}); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{
			r.Host, r.IP, strconv.Itoa(r.Port), r.State, r.Service,
			strconv.FormatFloat(r.LatencyMS, 'f', 2, 64), r.Banner,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
