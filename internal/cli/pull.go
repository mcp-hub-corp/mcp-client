package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/security-mcp/mcp-client/internal/cache"
	"github.com/security-mcp/mcp-client/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	pullCmd.RunE = runPull
}

// runPull executes the pull command to pre-download a package
func runPull(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	ref := args[0]

	// Parse package reference (org/name@version)
	org, name, version, err := parsePackageRef(ref)
	if err != nil {
		return fmt.Errorf("invalid package reference %q: %w", ref, err)
	}

	// Create logger
	logger := createLogger(cfg.LogLevel)

	// Create registry client
	registryClient := registry.NewClient(cfg.RegistryURL)
	registryClient.SetLogger(logger)

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	logger.Info("resolving package", slog.String("package", fmt.Sprintf("%s/%s", org, name)), slog.String("ref", version))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Resolve package reference to get manifest and bundle info
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	manifestDigest := resolveResp.Resolved.Manifest.Digest
	bundleDigest := resolveResp.Resolved.Bundle.Digest
	bundleSize := resolveResp.Resolved.Bundle.SizeBytes

	logger.Info("package resolved",
		slog.String("version", resolveResp.Resolved.Version),
		slog.String("manifest_digest", manifestDigest),
		slog.String("bundle_digest", bundleDigest),
		slog.Int64("bundle_size", bundleSize),
	)

	// Check if manifest is already in cache
	if cacheStore.Exists(manifestDigest, "manifest") {
		logger.Info("manifest already cached", slog.String("digest", manifestDigest))
	} else {
		logger.Info("downloading manifest", slog.String("digest", manifestDigest))
		manifestData, err := registryClient.DownloadManifest(ctx, org, manifestDigest)
		if err != nil {
			return fmt.Errorf("failed to download manifest: %w", err)
		}

		// Validate digest
		if err := registry.ValidateDigest(manifestData, manifestDigest); err != nil {
			return fmt.Errorf("manifest digest validation failed: %w", err)
		}

		// Store in cache
		if err := cacheStore.PutManifest(manifestDigest, manifestData); err != nil {
			return fmt.Errorf("failed to cache manifest: %w", err)
		}

		logger.Info("manifest cached successfully",
			slog.String("digest", manifestDigest),
			slog.Int("size", len(manifestData)),
		)
	}

	// Check if bundle is already in cache
	if cacheStore.Exists(bundleDigest, "bundle") {
		logger.Info("bundle already cached", slog.String("digest", bundleDigest))
		fmt.Printf("Pulling %s/%s@%s\n", org, name, resolveResp.Resolved.Version)
		fmt.Printf("Already cached: %s\n", bundleDigest[:19])
	} else {
		logger.Info("downloading bundle", slog.String("digest", bundleDigest), slog.Int64("size", bundleSize))
		fmt.Printf("Pulling %s/%s@%s\n", org, name, resolveResp.Resolved.Version)
		fmt.Printf("Downloading bundle: %s (%s)\n", bundleDigest[:19], formatSize(bundleSize))

		bundleData, err := registryClient.DownloadBundle(ctx, org, bundleDigest)
		if err != nil {
			return fmt.Errorf("failed to download bundle: %w", err)
		}

		// Validate digest
		if err := registry.ValidateDigest(bundleData, bundleDigest); err != nil {
			return fmt.Errorf("bundle digest validation failed: %w", err)
		}

		// Store in cache
		if err := cacheStore.PutBundle(bundleDigest, bundleData); err != nil {
			return fmt.Errorf("failed to cache bundle: %w", err)
		}

		logger.Info("bundle cached successfully",
			slog.String("digest", bundleDigest),
			slog.Int("size", len(bundleData)),
		)

		fmt.Printf("Downloaded and cached successfully\n")
	}

	fmt.Printf("Package ready: %s@%s\n", fmt.Sprintf("%s/%s", org, name), resolveResp.Resolved.Version)

	return nil
}

// parsePackageRef parses a package reference in format "org/name@ref"
func parsePackageRef(ref string) (org, name, version string, err error) {
	// Split by @ to separate name and version
	parts := strings.Split(ref, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("expected format org/name@version")
	}

	orgName := parts[0]
	version = parts[1]

	// Split org/name
	orgNameParts := strings.Split(orgName, "/")
	if len(orgNameParts) != 2 {
		return "", "", "", fmt.Errorf("expected format org/name@version")
	}

	org = orgNameParts[0]
	name = orgNameParts[1]

	if org == "" || name == "" || version == "" {
		return "", "", "", fmt.Errorf("org, name, and version cannot be empty")
	}

	return org, name, version, nil
}

// formatSize formats a byte size into a human-readable string
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp > 0 && exp <= len(units) {
		return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp-1])
	}

	return fmt.Sprintf("%d B", bytes)
}

// createLogger creates a structured logger with the specified level
func createLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}
