package ai

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ClaudeCodeClient uses the Claude Code CLI as the AI backend.
// This uses the CLI's existing authentication — no API key needed.
type ClaudeCodeClient struct {
	binary string // path to claude CLI
}

// NewClaudeCodeClient creates a client that pipes through the claude CLI.
func NewClaudeCodeClient() *ClaudeCodeClient {
	// Find claude binary
	binary, err := exec.LookPath("claude")
	if err != nil {
		binary = "/home/fernald/.local/bin/claude"
	}
	return &ClaudeCodeClient{binary: binary}
}

func (c *ClaudeCodeClient) Chat(ctx context.Context, systemPrompt string, messages []Message, onChunk func(string)) error {
	// Build the prompt: system context + conversation history
	var prompt strings.Builder
	prompt.WriteString(systemPrompt)
	prompt.WriteString("\n\n")

	for _, m := range messages {
		if m.Role == "user" {
			prompt.WriteString("User: ")
			prompt.WriteString(m.Content)
			prompt.WriteString("\n\n")
		} else if m.Role == "assistant" {
			prompt.WriteString("Assistant: ")
			prompt.WriteString(m.Content)
			prompt.WriteString("\n\n")
		}
	}

	// Run claude --print with the full prompt piped to stdin
	cmd := exec.CommandContext(ctx, c.binary, "--print")
	cmd.Stdin = bytes.NewBufferString(prompt.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		return fmt.Errorf("claude CLI: %s", errMsg)
	}

	response := strings.TrimSpace(stdout.String())
	if response != "" {
		onChunk(response)
	}

	return nil
}

// ChatSync collects the full response.
func (c *ClaudeCodeClient) ChatSync(ctx context.Context, systemPrompt string, messages []Message) (string, error) {
	var b strings.Builder
	err := c.Chat(ctx, systemPrompt, messages, func(chunk string) {
		b.WriteString(chunk)
	})
	return b.String(), err
}

// IsAvailable checks if the claude CLI is installed and accessible.
func IsClaudeCodeAvailable() bool {
	path, err := exec.LookPath("claude")
	if err != nil {
		// Check common install location
		path = "/home/fernald/.local/bin/claude"
	}
	_, err = exec.Command(path, "--version").Output()
	return err == nil
}
