package api

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/netguru/myra-external-dns-webhook/pkg/errors"
)

func (w webhook) ApplyChanges(ctx *fiber.Ctx) error {
	w.logger.Info("ApplyChanges endpoint called",
		zap.String("remote_ip", ctx.IP()),
		zap.String("method", ctx.Method()),
		zap.String("path", ctx.Path()),
		zap.String("user_agent", string(ctx.Request().Header.UserAgent())),
		zap.String("request_id", ctx.GetRespHeader("X-Request-ID", "-")),
		zap.Int("content_length", ctx.Request().Header.ContentLength()))

	var changes plan.Changes
	body := ctx.Body()
	if err := json.Unmarshal(body, &changes); err != nil {
		// If that fails, try to parse as array of endpoints
		w.logger.Debug("Failed to parse as plan.Changes, trying as array of endpoints",
			zap.String(logFieldError, err.Error()))

		var endpoints []*endpoint.Endpoint
		if err := json.Unmarshal(body, &endpoints); err != nil {
			w.logger.Error("Failed to parse request body as either plan.Changes or array of endpoints",
				zap.String(logFieldError, err.Error()))
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": errors.ErrInvalidJSONFormat.Error(),
			})
		}

		// Successfully parsed as array of endpoints
		w.logger.Debug("Parsed request as array of endpoints",
			zap.Int("count", len(endpoints)))
	}

	w.logger.Debug(
		"Parsed changes",
		zap.Int("create_count", len(changes.Create)),
		zap.Int("delete_count", len(changes.Delete)),
		zap.Int("update_count", len(changes.UpdateNew)),
	)

	if err := w.provider.ApplyChanges(ctx.Context(), &changes); err != nil {
		w.logger.Error("Failed to apply changes",
			zap.String(logFieldError, err.Error()))

		switch {
		case err == errors.ErrMissingAPIKey:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "API key is required",
			})
		case err == errors.ErrMissingAPISecret:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "API secret is required",
			})
		case err == errors.ErrDomainNotFound:
			return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Domain not found",
			})
		case err == errors.ErrAPIRequestFailed:
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "API request to MyraSec failed",
			})
		default:
			// For other errors, return a generic error message
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Failed to apply DNS changes",
				"details": err.Error(),
			})
		}
	}

	ctx.Response().Header.Set("Content-Type", MediaTypeFormatAndVersion)
	ctx.Status(fiber.StatusNoContent)
	return nil
}
