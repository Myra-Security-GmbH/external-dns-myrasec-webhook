package api

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"

	"github.com/netguru/myra-external-dns-webhook/pkg/errors"
)

func (w webhook) AdjustEndpointsHandler(ctx *fiber.Ctx) error {
	w.logger.Info("AdjustEndpoints endpoint called",
		zap.String("remote_ip", ctx.IP()),
		zap.String("method", ctx.Method()),
		zap.String("path", ctx.Path()),
		zap.String("user_agent", string(ctx.Request().Header.UserAgent())),
		zap.String("request_id", ctx.GetRespHeader("X-Request-ID", "-")),
		zap.Int("content_length", ctx.Request().Header.ContentLength()))

	// Log the raw request body for debugging
	body := ctx.Body()
	w.logger.Debug("Raw request body", zap.String("body", string(body)))

	// Manually parse the JSON
	var request endpointsRequest
	if err := json.Unmarshal(body, &request); err != nil {
		// Try the old way as a fallback
		var endpoints []*endpoint.Endpoint
		if fallbackErr := json.Unmarshal(body, &endpoints); fallbackErr != nil {
			w.logger.Error("Error parsing request body",
				zap.Error(err),
				zap.String("primary_error", err.Error()),
				zap.String("fallback_error", fallbackErr.Error()),
				zap.String("raw_body", string(body)))

			ctx.Response().Header.Set(contentTypeHeader, contentTypePlaintext)
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   errors.ErrInvalidJSONFormat.Error(),
				"details": "Request body could not be parsed as either structured format or array format",
			})
		}

		w.logger.Debug("Parsed request using fallback array method",
			zap.Int("endpoint_count", len(endpoints)),
			zap.String("format", "array"))

		adjustedEndpoints, err := w.provider.AdjustEndpoints(endpoints)
		if err != nil {
			w.logger.Error("Error adjusting endpoints",
				zap.Error(err),
				zap.String("error_type", "provider_error"))

			ctx.Response().Header.Set(contentTypeHeader, contentTypePlaintext)
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   errors.ErrAPIRequestFailed.Error(),
				"details": err.Error(),
			})
		}

		w.logger.Debug("Adjusted endpoints successfully",
			zap.Int("original_count", len(endpoints)),
			zap.Int("adjusted_count", len(adjustedEndpoints)))

		ctx.Set(varyHeader, contentTypeHeader)
		ctx.Response().Header.Set("Content-Type", MediaTypeFormatAndVersion)
		response, err := json.Marshal(adjustedEndpoints)
		if err != nil {
			w.logger.Error("Failed to marshal adjusted endpoints response",
				zap.Error(err))
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Failed to marshal adjusted endpoints response",
				"details": err.Error(),
			})
		}
		return ctx.Send(response)
	} else {
		return errors.ErrInvalidJSONFormat
	}

}
