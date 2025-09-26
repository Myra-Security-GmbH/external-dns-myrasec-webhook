package cmd

import (
	"fmt"
	"strconv"

	"github.com/netguru/myra-external-dns-webhook/internal/myrasecprovider"
	"github.com/netguru/myra-external-dns-webhook/pkg/api"

	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sigs.k8s.io/external-dns/endpoint"
)

var (
	listenAddress    string
	myraSecAPIKey    string
	myraSecAPISecret string
	baseURL          string
	dryRun           bool
	logLevel         string
	domainFilter     []string
	ttl              int
)

var rootCmd = &cobra.Command{
	Use:   "external-dns-myrasec-webhook",
	Short: "Webhook myrasecprovider for ExternalDNS to manage MyraSec DNS records",
	Long:  "Webhook myrasecprovider for ExternalDNS to manage MyraSec DNS records through the MyraSec API",
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize logger
		logger := getLogger()
		defer func() {
			if err := logger.Sync(); err != nil {
				fmt.Printf("Failed to sync logger: %v\n", err)
			}
		}()

		// Validate required parameters
		if listenAddress == "" {
			logger.Fatal("ERROR: Listen address is required but not set. Please set WEBHOOK_LISTEN_ADDRESS_PORT or WEBHOOK_LISTEN_ADDRESS environment variable.")
		}

		if myraSecAPIKey == "" {
			logger.Fatal("ERROR: MYRASEC_API_KEY is required but not set.")
		}

		if myraSecAPISecret == "" {
			logger.Fatal("ERROR: MYRASEC_API_SECRET is required but not set.")
		}

		logger.Info("All required configuration parameters are present")

		// Initialize domain filter
		domainFilter := endpoint.DomainFilter{Filters: domainFilter}

		// Initialize MyraSec myrasecprovider
		myraSecProvider, err := myrasecprovider.NewMyraSecDNSProvider(
			logger.With(zap.String("component", "myrasecprovider")),
			myrasecprovider.Config{
				APIKey:       myraSecAPIKey,
				APISecret:    myraSecAPISecret,
				BaseURL:      baseURL,
				DomainFilter: domainFilter,
				DryRun:       dryRun,
				TTL:          ttl,
			},
		)
		if err != nil {
			logger.Fatal("Failed to initialize MyraSec myrasecprovider", zap.Error(err))
		}

		// Initialize API server
		app := api.New(logger.With(zap.String("component", "api")), myraSecProvider)

		// Start listening for API requests
		logger.Info("Starting webhook server", zap.String("address", listenAddress))
		go func() {
			if err := app.Listen(listenAddress); err != nil {
				logger.Fatal("Failed to start server", zap.Error(err))
			}
		}()

		// Wait for termination signal
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("Shutting down server")
	},
}

// getLogger creates a new logger with the configured log level
func getLogger() *zap.Logger {
	cfg := zap.Config{
		Level:             zap.NewAtomicLevelAt(getZapLogLevel()),
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Encoding:          "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := cfg.Build()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	logger.Info("Logger initialized", zap.String("level", logLevel))
	return logger
}

// getZapLogLevel converts the string log level to a zap log level
func getZapLogLevel() zapcore.Level {
	switch strings.ToLower(logLevel) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Define command line flags
	rootCmd.PersistentFlags().StringVar(&listenAddress, "listen-address", "", "The address to listen on for HTTP requests")
	rootCmd.PersistentFlags().StringVar(&myraSecAPIKey, "myrasec-api-key", "", "The MyraSec API key to use for authentication")
	rootCmd.PersistentFlags().StringVar(&myraSecAPISecret, "myrasec-api-secret", "", "The MyraSec API secret to use for authentication")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "If true, only print the changes that would be made")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "The log level to use (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringSliceVar(&domainFilter, "domain-filter", []string{}, "Filter domain names to manage")
}

func initConfig() {
	// Load environment variables from .env file if it exists
	// This is especially useful for local development
	if err := godotenv.Load(); err != nil {
		// It's okay if the .env file doesn't exist in production
		log.Printf("Note: .env file not found, using environment variables")
	} else {
		log.Printf("Loaded configuration from .env file")
	}

	// Set up environment variable handling
	viper.SetEnvPrefix("WEBHOOK")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Map environment variables to flags
	if os.Getenv("WEBHOOK_LISTEN_ADDRESS_PORT") != "" {
		listenAddress = ":" + os.Getenv("WEBHOOK_LISTEN_ADDRESS_PORT")
	} else if os.Getenv("WEBHOOK_LISTEN_ADDRESS") != "" {
		listenAddress = os.Getenv("WEBHOOK_LISTEN_ADDRESS")
	}

	// Set default listen address if not provided
	if listenAddress == "" {
		listenAddress = ":8080"
		log.Printf("No listen address configured, using default: %s", listenAddress)
	}

	if os.Getenv("MYRASEC_API_KEY") != "" && myraSecAPIKey == "" {
		myraSecAPIKey = os.Getenv("MYRASEC_API_KEY")
	}

	if os.Getenv("MYRASEC_API_SECRET") != "" && myraSecAPISecret == "" {
		myraSecAPISecret = os.Getenv("MYRASEC_API_SECRET")
	}

	if os.Getenv("BASE_URL") != "" && baseURL == "" {
		baseURL = os.Getenv("BASE_URL")
	}

	// Check for optional environment variables
	if os.Getenv("DRY_RUN") == "true" && !dryRun {
		dryRun = true
	}

	if os.Getenv("LOG_LEVEL") != "" && logLevel == "info" {
		logLevel = os.Getenv("LOG_LEVEL")
	}

	if os.Getenv("DOMAIN_FILTER") != "" && len(domainFilter) == 0 {
		domainFilter = strings.Split(os.Getenv("DOMAIN_FILTER"), ",")
	}
	if os.Getenv("TTL") != "" {
		ttlvar, _ := strconv.Atoi(os.Getenv("TTL"))
		if ttlvar > 0 {
			ttl = ttlvar
		}
	} else {
		ttl = 300
		log.Printf("No TTL configured, using default: %d", ttl)
	}
	if os.Getenv("ENV") != "" {
		log.Printf("Enviroment: %s", os.Getenv("ENV"))
	}

	// Bind viper environment variables to flags
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			if err := rootCmd.PersistentFlags().Set(f.Name, fmt.Sprint(val)); err != nil {
				log.Printf("Warning: Failed to set flag %s from environment variable: %v", f.Name, err)
			}
		}
	})
}
