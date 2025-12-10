package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

type GitHubItem struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // "file" or "dir"
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
}

func fetchGitHubFolder(owner, repo, folder string) ([]GitHubItem, error) {
	resp, err := http.Get(fmt.Sprintf("https://api.github.com/repos/lab313ru/psx_psyq_signatures/contents/%s", folder))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}
	var items []GitHubItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
}

type Labels struct {
	Name   string `json:"name"`
	Offset uint32 `json:"offset"`
}
type Signature struct {
	Name      string   `json:"name"`
	Signature string   `json:"sig"`
	Labels    []Labels `json:"labels,omitempty"`
	Bss       []Labels `json:"xbss,omitempty"`
	signature []byte
	wildcard  []bool
}

func fetchPsyqSignatures(sdkver string) ([]Signature, error) {
	files, err := fetchGitHubFolder("lab313ru", "psx_psyq_signatures", sdkver)
	if err != nil {
		return nil, err
	}
	var signatures []Signature
	var mu sync.Mutex
	var eg errgroup.Group
	for _, file := range files {
		eg.Go(func() error {
			resp, err := http.Get(file.DownloadURL)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("GitHub API returned %s", resp.Status)
			}
			var items []Signature
			if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			signatures = append(signatures, items...)
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	for i, signature := range signatures {
		s := strings.Split(strings.ToLower(signature.Signature), " ")
		for _, ch := range s {
			if ch == "??" {
				signature.wildcard = append(signature.wildcard, true)
				signature.signature = append(signature.signature, 0)
				continue
			}
			if ch == "" {
				continue
			}
			b, err := strconv.ParseUint(ch, 16, 8)
			if err != nil {
				return nil, err
			}
			signature.wildcard = append(signature.wildcard, false)
			signature.signature = append(signature.signature, byte(b))
		}
		signatures[i] = signature
	}
	return signatures, nil
}

func checkSignature(b []byte, signature Signature) (Signature, int) {
	sigLen := len(signature.signature)
	if sigLen == 0 {
		return Signature{}, -1
	}
	for i := 0; i < len(b)-sigLen; i++ {
		start := b[i:]
		match := true
		for j := 0; j < sigLen; j++ {
			if signature.wildcard[j] {
				continue
			}
			if start[j] != signature.signature[j] {
				match = false
				break
			}
		}
		if match {
			return signature, i
		}
	}
	return Signature{}, -1
}

type match struct {
	start   int
	end     int
	name    string
	version string
	symbols map[uint32]string
}

func getMatches(b []byte, baseAddr uint32, sdkver string) []match {
	signatures, err := fetchPsyqSignatures(sdkver)
	if err != nil {
		log.Fatal(err)
	}
	var matches []match
	for _, signature := range signatures {
		sig, offset := checkSignature(b, signature)
		if offset < 0 {
			continue
		}
		m := match{
			start:   offset,
			end:     offset + len(sig.signature),
			name:    sig.Name,
			version: sdkver,
			symbols: map[uint32]string{},
		}
		for _, label := range sig.Labels {
			if strings.HasPrefix(label.Name, "loc_") {
				continue
			}
			if strings.HasPrefix(label.Name, "text_") {
				continue
			}
			m.symbols[baseAddr+uint32(offset)+label.Offset] = label.Name
		}
		matches = append(matches, m)
	}
	return matches
}

type VersionEstimate struct {
	version string
	match   float64
}

func estimatePsyqVesion(matches map[string]match) []VersionEstimate {
	versions := make(map[string]int)
	for _, m := range matches {
		versions[m.version]++
	}
	total := float64(len(matches))
	out := make([]VersionEstimate, 0, len(versions))
	for v, count := range versions {
		out = append(out, VersionEstimate{
			version: v,
			match:   float64(count) / total,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].match < out[j].match
	})
	if len(out) >= 3 {
		out = out[:3]
	}
	return out
}

func getMatchesSorted(matches map[string]match) []match {
	out := make([]match, 0, len(matches))
	for _, m := range matches {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].start < out[j].start
	})
	return out
}

func getSymbolsSorted(matches map[string]match) []Labels {
	var out []Labels
	for _, m := range matches {
		for offset, name := range m.symbols {
			out = append(out, Labels{
				Name:   name,
				Offset: offset,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Offset < out[j].Offset
	})
	return out
}

func do(b []byte, baseAddr uint32) {
	versions := []string{
		"260", "300", "330", "340", "350", "3610", "3611", "370",
		"400", "410", "420", "430", "440", "450", "460", "470",
	}
	var eg errgroup.Group
	var mu sync.Mutex
	allMatches := map[string]match{}
	for _, ver := range versions {
		eg.Go(func() error {
			matches := getMatches(b, baseAddr, ver)
			if len(matches) == 0 {
				return nil
			}
			mu.Lock()
			defer mu.Unlock()
			for _, match := range matches {
				existingMatch, ok := allMatches[match.name]
				if !ok {
					allMatches[match.name] = match
					continue
				}
				// If the same match is found across different PSY-Q versions,
				// take the match with the highest symbol matches found
				if len(existingMatch.symbols) < len(match.symbols) {
					allMatches[match.name] = match
				}
			}
			return nil
		})
	}
	_ = eg.Wait()

	if len(allMatches) == 0 {
		log.Fatal("mo matches found, is it a valid PSX EXE?")
	}

	matches := getMatchesSorted(allMatches)
	symbols := getSymbolsSorted(allMatches)
	for _, ver := range estimatePsyqVesion(allMatches) {
		fmt.Printf("PSY-Q %s: %.2f\n", ver.version, ver.match)
	}
	fmt.Printf(" - [0x%X, c, %s]\n", matches[0].start, strings.ToLower(strings.TrimSuffix(matches[0].name, ".OBJ")))
	for i := 1; i < len(matches); i++ {
		if matches[i].start > matches[i-1].end {
			fmt.Printf(" - [0x%X, c]\n", matches[i-1].end)
		}
		fmt.Printf(" - [0x%X, c, %s]\n", matches[i].start, strings.ToLower(strings.TrimSuffix(matches[i].name, ".OBJ")))
	}
	for _, symbol := range symbols {
		fmt.Printf("%s = 0x%08X\n", symbol.Name, baseAddr+symbol.Offset)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <psx.exe>\n", os.Args[0])
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if len(data) <= 0x800 {
		log.Fatal("file too small?")
	}
	do(data[0x800:], 0x80010000)
}
