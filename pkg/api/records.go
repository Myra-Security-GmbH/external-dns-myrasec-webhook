package api

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

func (w webhook) Records(ctx *fiber.Ctx) error {
	w.logger.Info("Records endpoint called",
		zap.String("remote_ip", ctx.IP()),
		zap.String("method", ctx.Method()),
		zap.String("path", ctx.Path()),
		zap.String("user_agent", string(ctx.Request().Header.UserAgent())),
		zap.String("request_id", ctx.GetRespHeader("X-Request-ID", "-")))

	// Get records from the provider
	w.logger.Debug("Calling provider.Records")
	records, err := w.provider.Records(ctx.UserContext())
	if err != nil {
		w.logger.Error("Failed to get records from provider",
			zap.Error(err),
			zap.String("error_type", "provider_error"))

		// Return appropriate error based on the error type
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to retrieve DNS records",
			"details": err.Error(),
		})
	}

	// If no records were returned, log a warning but return an empty array (not an error)
	if len(records) == 0 {
		w.logger.Warn("No records returned from provider")
	}

	w.logger.Debug("Returning records",
		zap.Int("count", len(records)))

	// Marshal the response manually
	response, err := json.Marshal(records)
	if err != nil {
		w.logger.Error("Failed to marshal records response",
			zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to marshal records response",
		})
	}

	ctx.Response().Header.Set("Vary", "Accept-Encoding")
	ctx.Response().Header.Set("Content-Type", MediaTypeFormatAndVersion)

	return ctx.Send(response)
}
