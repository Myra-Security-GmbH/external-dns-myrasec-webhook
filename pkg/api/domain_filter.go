package api

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"github.com/netguru/myra-external-dns-webhook/pkg/errors"
	"go.uber.org/zap"
)

func (w webhook) GetDomainFilter(ctx *fiber.Ctx) error {
	w.logger.Info("GetDomainFilter endpoint called",
		zap.String("remote_ip", ctx.IP()),
		zap.String("method", ctx.Method()),
		zap.String("path", ctx.Path()),
		zap.String("user_agent", string(ctx.Request().Header.UserAgent())),
		zap.String("request_id", ctx.GetRespHeader("X-Request-ID", "-")))

	// Get domain filter from the provider
	domainFilterInterface, err := json.Marshal(w.provider.GetDomainFilter())
	if err != nil {
		w.logger.Error("Failed to marshal domain filter response",
			zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to marshal domain filter response",
			"details": err.Error(),
		})
	}

	if domainFilterInterface == nil {
		w.logger.Error("Domain filter is nil, provider returned no domain filter")
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   errors.ErrMissingZone.Error(),
			"details": "Provider returned no domain filter",
		})
	}
	ctx.Response().Header.Set("Content-Type", MediaTypeFormatAndVersion)

	return ctx.Send(domainFilterInterface)
}
