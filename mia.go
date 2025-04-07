// main.go
package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"sync"
	"unicode"

	"github.com/spf13/cobra"
)

func printASCIIArt() {
	fmt.Println(`
    __  ____      
   /  |/  (_)___ _
  / /|_/ / / __ '/
 / /  / / / /_/ / 
/_/  /_/_/\__,_/  
                  
  Codename: Pain 
  Made with love <3    
  -Wired & Fuwa
`)
}

var (
	payload     string
	file        string
	outFile     string
	bitFlip     bool
	urlEncoding bool
	caseToggle  bool
	reversal    bool
)

func main() {
	printASCIIArt() // Print banner first
	Execute()
}

var rootCmd = &cobra.Command{
	Use:   "mia",
	Short: "Mia - A payload mutation CLI tool for fuzzers and pentesters",
	Long:  `Mia is a CLI utility that generates mutated payloads for fuzzing, evading filters, and testing web applications.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var mutateCmd = &cobra.Command{
	Use:   "mutate",
	Short: "Mutate a given payload using selected techniques",
	Run: func(cmd *cobra.Command, args []string) {
		opts := MutationOptions{
			EnableBitFlip:     bitFlip,
			EnableURLEncoding: urlEncoding,
			EnableCaseToggle:  caseToggle,
			EnableReversal:    reversal,
		}

		// If a file is provided, process it line by line.
		if file != "" {
			processFile(file, opts)
		} else if payload != "" {
			// Process a single payload string.
			results := MutatePayload(payload, opts)
			outputResults(results)
		} else {
			fmt.Println("You must provide --payload or --file")
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(mutateCmd)

	mutateCmd.Flags().StringVar(&payload, "payload", "", "Payload string to mutate")
	mutateCmd.Flags().StringVar(&file, "file", "", "Path to file with payload(s)")
	mutateCmd.Flags().StringVar(&outFile, "out", "", "File to write output to")
	mutateCmd.Flags().BoolVar(&bitFlip, "bitflip", true, "Enable bit-flip mutations")
	mutateCmd.Flags().BoolVar(&urlEncoding, "urlencode", true, "Enable URL encoding mutations")
	mutateCmd.Flags().BoolVar(&caseToggle, "casetoggle", false, "Enable case toggle mutations")
	mutateCmd.Flags().BoolVar(&reversal, "reverse", false, "Enable reverse mutation")
}

func outputResults(results []string) {
	if outFile != "" {
		err := os.WriteFile(outFile, []byte(joinLines(results)), 0644)
		if err != nil {
			fmt.Println("Failed to write output file:", err)
		}
	} else {
		for _, m := range results {
			fmt.Println(m)
		}
	}
}

func joinLines(lines []string) string {
	result := ""
	for _, line := range lines {
		result += line + "\n"
	}
	return result
}

// processFile reads the file line by line, mutates each line, and outputs the results.
func processFile(filename string, opts MutationOptions) {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Failed to open file:", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var allResults []string
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		// Process each line individually.
		results := MutatePayload(line, opts)
		allResults = append(allResults, results...)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

	outputResults(allResults)
}

// MutationOptions holds flags for which mutation techniques to apply.
type MutationOptions struct {
	EnableBitFlip     bool
	EnableURLEncoding bool
	EnableCaseToggle  bool
	EnableReversal    bool
}

// MutationTask represents a mutation job for the worker pool.
type MutationTask struct {
	Name    string
	Fn      func(string) []string
	Payload string
}

// runWorkerPool executes mutation tasks concurrently using a fixed number of workers.
func runWorkerPool(tasks []MutationTask, numWorkers int) []string {
	taskChan := make(chan MutationTask)
	resultChan := make(chan []string)
	var wg sync.WaitGroup

	// Worker function: processes tasks from the taskChan.
	worker := func() {
		defer wg.Done()
		for task := range taskChan {
			res := task.Fn(task.Payload)
			resultChan <- res
		}
	}

	// Start workers.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	// Feed tasks to the workers.
	go func() {
		for _, task := range tasks {
			taskChan <- task
		}
		close(taskChan)
	}()

	// Close the result channel once all workers are done.
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect and de-duplicate results.
	mutationSet := make(map[string]bool)
	for res := range resultChan {
		for _, m := range res {
			mutationSet[m] = true
		}
	}

	var mutations []string
	for m := range mutationSet {
		mutations = append(mutations, m)
	}
	return mutations
}

// MutatePayload creates tasks for each enabled mutation technique and uses the worker pool.
func MutatePayload(payload string, opts MutationOptions) []string {
	mutationSet := make(map[string]bool)
	mutationSet[payload] = true

	var tasks []MutationTask
	if opts.EnableBitFlip {
		tasks = append(tasks, MutationTask{Name: "bitflip", Fn: BitFlipMutations, Payload: payload})
	}
	if opts.EnableURLEncoding {
		tasks = append(tasks, MutationTask{Name: "urlencode", Fn: URLEncodingMutations, Payload: payload})
	}
	if opts.EnableCaseToggle {
		tasks = append(tasks, MutationTask{Name: "casetoggle", Fn: CaseToggleMutations, Payload: payload})
	}
	if opts.EnableReversal {
		tasks = append(tasks, MutationTask{Name: "reverse", Fn: ReverseMutation, Payload: payload})
	}

	// Use a worker pool to process mutation tasks concurrently.
	if len(tasks) > 0 {
		numWorkers := len(tasks)
		results := runWorkerPool(tasks, numWorkers)
		for _, m := range results {
			mutationSet[m] = true
		}
	}

	var out []string
	for m := range mutationSet {
		out = append(out, m)
	}
	return out
}

// BitFlipMutations generates payload mutations by flipping each bit in the payload.
func BitFlipMutations(payload string) []string {
	var mutations []string
	bytesPayload := []byte(payload)
	for i, b := range bytesPayload {
		for bit := 0; bit < 8; bit++ {
			mutated := make([]byte, len(bytesPayload))
			copy(mutated, bytesPayload)
			mutated[i] = b ^ (1 << uint(bit))
			mutations = append(mutations, string(mutated))
		}
	}
	return mutations
}

// URLEncodingMutations generates a mutation by applying URL encoding to the payload.
func URLEncodingMutations(payload string) []string {
	encoded := url.QueryEscape(payload)
	return []string{encoded}
}

// CaseToggleMutations toggles the case of each letter in the payload.
func CaseToggleMutations(payload string) []string {
	var mutations []string
	runes := []rune(payload)
	for i, r := range runes {
		if unicode.IsLetter(r) {
			toggled := make([]rune, len(runes))
			copy(toggled, runes)
			if unicode.IsUpper(r) {
				toggled[i] = unicode.ToLower(r)
			} else {
				toggled[i] = unicode.ToUpper(r)
			}
			mutations = append(mutations, string(toggled))
		}
	}
	return mutations
}

// ReverseMutation returns a single mutation which is the reversed payload.
func ReverseMutation(payload string) []string {
	runes := []rune(payload)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return []string{string(runes)}
}
