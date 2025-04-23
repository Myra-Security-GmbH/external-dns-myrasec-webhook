package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/pprof"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/provider"

	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
)

type Api interface {
	Listen(port string) error
	Test(req *http.Request, msTimeout ...int) (resp *http.Response, err error)
}

type api struct {
	logger *zap.Logger
	app    *fiber.App
}

func (a api) Test(req *http.Request, msTimeout ...int) (resp *http.Response, err error) {
	return a.app.Test(req, msTimeout...)
}

func (a api) Listen(address string) error {
	go func() {
		// Parse the address to ensure proper binding
		listenAddress := address

		// If the address starts with "localhost:", replace it with ":" to bind to all interfaces
		if strings.HasPrefix(address, "localhost:") {
			listenAddress = ":" + strings.Split(address, ":")[1]
			a.logger.Info("Changed listen address from localhost to all interfaces",
				zap.String("original", address),
				zap.String("new", listenAddress))
		} else if !strings.Contains(address, ":") {
			// If no colon, assume it's just a port number
			listenAddress = ":" + address
		}

		a.logger.Debug("Starting server", zap.String("address", listenAddress))
		err := a.app.Listen(listenAddress)
		if err != nil {
			a.logger.Fatal("Error starting the server", zap.String("error", err.Error()))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigCh

	a.logger.Info(
		"shutting down server due to received signal",
		zap.String("signal", sig.String()),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := a.app.ShutdownWithContext(ctx)
	if err != nil {
		a.logger.Error("error shutting down server", zap.String("error", err.Error()))
	}

	cancel()

	return err
}

//go:generate mockgen -destination=./mock/api.go -source=./api.go Provider
type Provider interface {
	provider.Provider
}

func New(logger *zap.Logger, provider provider.Provider) Api {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			logger.Error("Unhandled error in request",
				zap.Error(err),
				zap.String("path", c.Path()),
				zap.String("method", c.Method()),
				zap.String("ip", c.IP()))

			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Public health endpoint (no auth required)
	app.Get("/healthz", Health)

	// Global middleware
	app.Use(requestid.New())
	app.Use(fiberlogger.New())
	app.Use(pprof.New(pprof.Config{Prefix: "/pprof"}))
	app.Use(fiberrecover.New())
	app.Use(helmet.New())

	webhookRoutes := webhook{
		provider: provider,
		logger:   logger,
	}

	// Create a group for authenticated routes
	apiGroup := app.Group("/")

	// Register routes with authentication
	apiGroup.Get("/", webhookRoutes.GetDomainFilter)
	apiGroup.Get("/records", webhookRoutes.Records)
	apiGroup.Post("/records", webhookRoutes.ApplyChanges)
	apiGroup.Post("/adjustendpoints", webhookRoutes.AdjustEndpointsHandler)

	// Add compatibility routes for ExternalDNS
	apiGroup.Get("/webhook", webhookRoutes.GetDomainFilter)

	return &api{
		logger: logger,
		app:    app,
	}
}
