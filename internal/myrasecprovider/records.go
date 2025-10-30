package myrasecprovider

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
)

func (p *MyraSecDNSProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	p.logger.Debug("Attempting to list domains (Records)")

	selectedDomain, err := p.SelectDomain()
	if err != nil {
		p.logger.Error("Failed to select domain", zap.Error(err))
		return nil, err
	}

	p.logger.Debug("Selected domain for Records method",
		zap.String("domain_name", selectedDomain.Name),
		zap.Int("domain_id", selectedDomain.ID))

	dnsRecords, err := p.apiClient.ListDNSRecords(selectedDomain.ID, nil)
	if err != nil {
		p.logger.Error("Failed to list DNS records",
			zap.String("domain", selectedDomain.Name),
			zap.Error(err))
		return nil, fmt.Errorf("failed listing records: %w", err)
	}

	p.logger.Debug("DNS records retrieved", zap.Int("count", len(dnsRecords)))

	var endpoints []*endpoint.Endpoint
	txtRecords := make(map[string]string)

	// First, collect TXT records for ownership checks
	for _, r := range dnsRecords {
		if r.RecordType == endpoint.RecordTypeTXT {
			txtRecords[r.Name] = r.Value
		}
	}

	// Process non-TXT records
	for _, r := range dnsRecords {
		if !supportedRecordType(r.RecordType) {
			continue
		}

		dnsName := ensureTrailingDot(r.Name)
		if !p.domainFilter.Match(dnsName) {
			continue
		}

		// Validate ownership for non-TXT records
		if r.RecordType != endpoint.RecordTypeTXT {
			txtVal, ok := txtRecords[r.Name]
			if !ok || !isOwnedByExternalDNS(txtVal, p.owner) {
				continue
			}
		} else {
			// TXT records: must be owned
			if !isOwnedByExternalDNS(r.Value, p.owner) {
				continue
			}
		}

		ep := endpoint.NewEndpoint(dnsName, r.RecordType, r.Value)
		if r.TTL > 0 {
			ep.RecordTTL = endpoint.TTL(r.TTL)
		}

		ep.Labels = map[string]string{
			endpoint.OwnerLabelKey: p.owner,
		}

		// Add resource label if present
		if resource := extractResourceFromTXT(r.Value); resource != "" {
			ep.Labels[endpoint.ResourceLabelKey] = resource
		}

		p.logger.Debug("Added endpoint",
			zap.String("dnsName", ep.DNSName),
			zap.String("recordType", ep.RecordType),
			zap.Any("targets", ep.Targets))

		endpoints = append(endpoints, ep)
	}

	p.logger.Info("Processed DNS records",
		zap.Int("total", len(dnsRecords)),
		zap.Int("filtered", len(endpoints)))

	return endpoints, nil
}

func extractResourceFromTXT(txtValue string) string {
	parts := strings.Split(txtValue, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "external-dns/resource=") {
			return strings.TrimPrefix(part, "external-dns/resource=")
		}
	}
	return ""
}
func (p *MyraSecDNSProvider) processCreateActions(endpoints []*endpoint.Endpoint) error {
	for _, ep := range endpoints {

		dnsName := p.ensureFullDNSName(stripTrailingDot(ep.DNSName))

		// If skipping private IP in production, handle here too:
		if isProduction() && isPrivateEndpoint(ep) {
			p.logger.Warn("Skipping creation of private IP record in production",
				zap.String("dnsName", dnsName),
				zap.String("recordType", ep.RecordType))
			continue
		}
		// Set TTL
		ttl := p.ttl
		if ep.RecordTTL > 0 {
			ttl = int(ep.RecordTTL)
		}

		// Format labels
		if ep.Labels == nil {
			ep.Labels = map[string]string{}
		}
		ep.Labels[endpoint.OwnerLabelKey] = p.owner

		// Loop through targets
		for _, target := range ep.Targets {
			val := p.formatRecordValue(target, ep.RecordType)

			// Create record
			err := p.createDNSRecord(dnsName, ep.RecordType, val, ttl)
			if err != nil {
				p.logger.Error("Failed to create DNS record", zap.String("dnsName", dnsName), zap.String("type", ep.RecordType), zap.String("value", val), zap.Error(err))
				return err
			}
		}

		// If non-TXT record, also create corresponding TXT record to declare ownership
		if ep.RecordType != endpoint.RecordTypeTXT {
			txtVal := fmt.Sprintf("heritage=external-dns,external-dns/owner=%s", p.owner)
			if resource, ok := ep.Labels[endpoint.ResourceLabelKey]; ok {
				txtVal += fmt.Sprintf(",external-dns/resource=%s", resource)
			}

			err := p.createDNSRecord(dnsName, endpoint.RecordTypeTXT, txtVal, ttl)
			if err != nil {
				p.logger.Error("Failed to create TXT ownership record", zap.String("dnsName", dnsName), zap.String("value", txtVal), zap.Error(err))
				return err
			}
		}
	}
	return nil
}

func (p *MyraSecDNSProvider) processUpdateActions(oldEndpoints, newEndpoints []*endpoint.Endpoint) error {
	if len(oldEndpoints) != len(newEndpoints) {
		return fmt.Errorf("mismatched endpoint lists: old=%d, new=%d", len(oldEndpoints), len(newEndpoints))
	}

	// Fetch domain-wide records once
	domainID, err := strconv.Atoi(p.domainId)
	if err != nil {
		return fmt.Errorf("invalid domain ID: %w", err)
	}
	allRecords, err := p.apiClient.ListDNSRecords(domainID, nil)
	if err != nil {
		return fmt.Errorf("failed to list DNS records for update: %w", err)
	}

	// Index TXT records for ownership checks
	txtRecords := make(map[string]string)
	for _, r := range allRecords {
		if r.RecordType == endpoint.RecordTypeTXT {
			txtRecords[r.Name] = r.Value
		}
	}

	for _, newEp := range newEndpoints {
		//oldEp := oldEndpoints[i]
		dnsName := p.ensureFullDNSName(stripTrailingDot(newEp.DNSName))

		if isProduction() && isPrivateEndpoint(newEp) {
			p.logger.Warn("Skipping private IP update in production", zap.String("dnsName", dnsName), zap.String("type", newEp.RecordType))
			continue
		}

		ttl := p.ttl
		if newEp.RecordTTL > 0 {
			ttl = int(newEp.RecordTTL)
		}

		// Ownership validation via corresponding TXT record
		if txtVal, ok := txtRecords[stripTrailingDot(newEp.DNSName)]; !ok || !isOwnedByExternalDNS(txtVal, p.owner) {
			p.logger.Warn("Skipping update: not owned by this instance", zap.String("dnsName", dnsName))
			continue
		}

		existingRecords := p.findMatchingRecords(allRecords, dnsName, newEp.RecordType)

		// Build set of current and desired values
		current := map[string]*myrasec.DNSRecord{}
		for _, rec := range existingRecords {
			current[rec.Value] = &rec
		}

		desired := map[string]struct{}{}
		for _, target := range newEp.Targets {
			desired[p.formatRecordValue(target, newEp.RecordType)] = struct{}{}
		}

		// 1. Update TTLs and modified values
		for val, rec := range current {
			if _, shouldExist := desired[val]; shouldExist {
				if rec.TTL != ttl || rec.Active != !p.disableProtection || rec.Name != dnsName {
					rec.TTL = ttl
					rec.Active = !p.disableProtection
					rec.Name = dnsName
					domainID, err := strconv.Atoi(p.domainId)
					if err != nil {
						p.logger.Error("Invalid domain ID", zap.Error(err))
						continue
					}
					if _, err := p.apiClient.UpdateDNSRecord(rec, domainID); err != nil {
						p.logger.Error("Failed to update record", zap.String("dnsName", dnsName), zap.String("value", val), zap.Error(err))
						return err
					}
					p.logger.Info("Updated record", zap.String("dnsName", dnsName), zap.String("value", val), zap.Int("ttl", ttl), zap.Bool("active", !p.disableProtection))
				}
				delete(desired, val) // Mark as processed so it's not created again later
			} else {
				err := p.deleteDNSRecord(rec)
				if err != nil {
					p.logger.Error("Failed to delete record during update",
						zap.String("dnsName", rec.Name),
						zap.String("type", rec.RecordType),
						zap.String("value", rec.Value),
						zap.Error(err))
					return err
				}
				p.logger.Info("Deleted record", zap.String("dnsName", dnsName), zap.String("type", rec.RecordType), zap.String("value", val))
			}
		}

		// 2. Create any missing records
		for val := range desired {
			if err := p.createDNSRecord(dnsName, newEp.RecordType, val, ttl); err != nil {
				p.logger.Error("Failed to create record during update", zap.String("dnsName", dnsName), zap.String("value", val), zap.Error(err))
				return err
			}
			p.logger.Info("Created missing record during update", zap.String("dnsName", dnsName), zap.String("value", val))
		}
	}
	return nil
}
func (p *MyraSecDNSProvider) processDeleteActions(endpoints []*endpoint.Endpoint) error {
	if len(endpoints) == 0 {
		return nil
	}

	// Fetch all records for the domain once
	domainID, err := strconv.Atoi(p.domainId)
	if err != nil {
		return fmt.Errorf("invalid domain ID: %w", err)
	}
	allRecords, err := p.apiClient.ListDNSRecords(domainID, nil)
	if err != nil {
		return fmt.Errorf("failed to list DNS records for deletion: %w", err)
	}

	// Index TXT records for ownership check
	txtRecords := make(map[string]string)
	for _, r := range allRecords {
		if r.RecordType == endpoint.RecordTypeTXT {
			txtRecords[r.Name] = r.Value
		}
	}

	for _, ep := range endpoints {
		dnsName := p.ensureFullDNSName(stripTrailingDot(ep.DNSName))

		if isProduction() && isPrivateEndpoint(ep) {
			p.logger.Warn("Skipping deletion of private IP in production",
				zap.String("dnsName", dnsName),
				zap.String("type", ep.RecordType))
			continue
		}

		// Ownership check
		txtVal, ok := txtRecords[stripTrailingDot(ep.DNSName)]
		if !ok || !isOwnedByExternalDNS(txtVal, p.owner) {
			p.logger.Warn("Skipping delete: not owned by this instance",
				zap.String("dnsName", dnsName))
			continue
		}

		// Find all records matching this dnsName + recordType
		matchingRecords := p.findMatchingRecords(allRecords, dnsName, ep.RecordType)
		if len(matchingRecords) == 0 {
			p.logger.Debug("No matching records to delete", zap.String("dnsName", dnsName), zap.String("type", ep.RecordType))
			continue
		}

		// Prepare target values to delete
		targetsToDelete := make(map[string]bool)
		for _, t := range ep.Targets {
			targetsToDelete[p.formatRecordValue(t, ep.RecordType)] = true
		}

		for _, record := range matchingRecords {
			if !targetsToDelete[record.Value] {
				continue
			}

			err := p.deleteDNSRecord(&record)
			if err != nil {
				p.logger.Error("Failed to delete DNS record",
					zap.String("dnsName", record.Name),
					zap.String("type", record.RecordType),
					zap.String("value", record.Value),
					zap.Error(err))
				return err
			}
		}
	}

	return nil
}

func isOwnedByExternalDNS(txtValue, owner string) bool {
	return strings.Contains(txtValue, "heritage=external-dns") &&
		strings.Contains(txtValue, fmt.Sprintf("external-dns/owner=%s", owner))
}

// createDNSRecord is the underlying method used by processCreateActions or processUpdateActions.
func (p *MyraSecDNSProvider) createDNSRecord(dnsName, recordType, value string, ttl int) error {
	formattedValue := p.formatRecordValue(value, recordType)
	record := &myrasec.DNSRecord{
		Name:       dnsName,
		Value:      formattedValue,
		RecordType: recordType,
		Active:     !p.disableProtection,
		Enabled:    true,
		TTL:        ttl,
	}

	domainID, err := strconv.Atoi(p.domainId)
	if err != nil {
		return fmt.Errorf("invalid domain ID: %w", err)
	}
	_, err = p.apiClient.CreateDNSRecord(record, domainID)
	if err != nil {
		// Duplicate record
		if strings.Contains(err.Error(), "This value is already used") {
			p.logger.Warn("Record already exists, skipping creation",
				zap.String("name", record.Name),
				zap.String("type", record.RecordType),
				zap.String("value", record.Value))
			return nil
		}

		// Private IP logic
		if strings.Contains(err.Error(), "private network range") && isProduction() {
			p.logger.Warn("Private IP address detected, skipping creation in production mode",
				zap.String("name", record.Name),
				zap.String("type", record.RecordType),
				zap.String("value", record.Value))
			return nil
		} else if strings.Contains(err.Error(), "private network range") {
			p.logger.Info("Creating DNS record with private IP in development mode",
				zap.String("name", record.Name),
				zap.String("type", record.RecordType),
				zap.String("value", record.Value))
			return nil // Myra might block it anyway. Or you handle differently.
		}

		p.logger.Error("Failed to create DNS record",
			zap.Error(err),
			zap.String("name", record.Name),
			zap.String("type", record.RecordType),
			zap.String("value", record.Value))
		return err
	}

	p.logger.Info("Created DNS record",
		zap.String("name", record.Name),
		zap.String("type", record.RecordType),
		zap.String("value", record.Value),
		zap.Int("ttl", record.TTL))
	return nil
}

// deleteDNSRecord is the underlying method used by processDeleteActions or processUpdateActions.
func (p *MyraSecDNSProvider) deleteDNSRecord(record *myrasec.DNSRecord) error {
	domainID, err := strconv.Atoi(p.domainId)
	if err != nil {
		p.logger.Error("Invalid domain ID", zap.Error(err))
		return nil
	}

	_, err = p.apiClient.DeleteDNSRecord(record, domainID)
	if err != nil {
		p.logger.Error("Failed to delete DNS record",
			zap.String("dnsName", record.Name),
			zap.String("type", record.RecordType),
			zap.String("value", record.Value),
			zap.Error(err))
		return err
	}

	p.logger.Info("Deleted DNS record",
		zap.String("dnsName", record.Name),
		zap.String("type", record.RecordType),
		zap.String("value", record.Value))
	return nil
}

// findMatchingRecords returns all records matching the given dnsName + recordType.
func (p *MyraSecDNSProvider) findMatchingRecords(records []myrasec.DNSRecord, dnsName, recordType string) []myrasec.DNSRecord {
	var matching []myrasec.DNSRecord
	for _, rec := range records {
		if stripTrailingDot(rec.Name) == stripTrailingDot(dnsName) && rec.RecordType == recordType {
			matching = append(matching, rec)
		}
	}
	return matching
}

// formatRecordValue cleans or adjusts the record value based on record type.
func (p *MyraSecDNSProvider) formatRecordValue(value, recordType string) string {
	if recordType == endpoint.RecordTypeTXT {
		return formatTXTValue(value)
	}
	return value
}

// ensureFullDNSName appends p.domainName if the dnsName is missing it.
func (p *MyraSecDNSProvider) ensureFullDNSName(dnsName string) string {
	if p.domainName == "" {
		return dnsName
	}
	// If it already ends with the domainName, skip
	if strings.HasSuffix(dnsName, p.domainName) {
		return dnsName
	}
	return dnsName + "." + p.domainName
}

// supportedRecordType returns true if the record type is supported by ExternalDNS.
func supportedRecordType(recordType string) bool {
	switch recordType {
	case endpoint.RecordTypeA, endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME,
		endpoint.RecordTypeMX, endpoint.RecordTypeTXT, endpoint.RecordTypeNS, endpoint.RecordTypeSRV:
		return true
	}
	return false
}

// isProduction checks if we're in a production-like environment.
// It returns true for environments that should have production behavior (e.g., prod, production, staging).
func isProduction() bool {
	env := strings.ToLower(os.Getenv("ENV"))

	// Consider these environments as production-like (requiring stricter rules)
	prodEnvs := map[string]bool{
		"prod":       true,
		"production": true,
		"staging":    true,
	}

	// If ENV is not set, default to non-production behavior
	return prodEnvs[env]
}

// isPrivateIP is a basic check for IPv4 private ranges or loopback.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateBlocks := []net.IPNet{
		// IPv4 private ranges
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}, // link-local
		// Loopback
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		// IPv6 loopback
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
	}

	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateEndpoint checks if any target is a private IP for A/AAAA records.
func isPrivateEndpoint(ep *endpoint.Endpoint) bool {
	if ep.RecordType == endpoint.RecordTypeA || ep.RecordType == endpoint.RecordTypeAAAA {
		for _, t := range ep.Targets {
			if isPrivateIP(t) {
				return true
			}
		}
	}
	return false
}

// formatTXTValue sanitizes a TXT record value by removing quotes, newlines, etc.
func formatTXTValue(value string) string {
	value = strings.Trim(value, "\"'")
	value = strings.ReplaceAll(value, "\"", "")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return value
}

// ensureTrailingDot ensures the given name ends with a dot (common in ExternalDNS).
func ensureTrailingDot(name string) string {
	if name == "" {
		return name
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// stripTrailingDot removes any final dot in a DNS name.
func stripTrailingDot(name string) string {
	if strings.HasSuffix(name, ".") {
		return name[:len(name)-1]
	}
	return name
}
