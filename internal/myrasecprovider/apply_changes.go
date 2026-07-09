package myrasecprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// ErrUpdateSlicesMismatch is returned when update slices have different lengths
var ErrUpdateSlicesMismatch = errors.New("update slices have different lengths")

// ApplyChangesWithWorkers applies DNS record changes using worker goroutines for parallel processing.
// This is an alternative to the sequential ApplyChanges implementation.
func (p *MyraSecDNSProvider) ApplyChangesWithWorkers(ctx context.Context, changes *plan.Changes) error {
	p.logger.Info("Applying DNS changes with workers",
		zap.Int("create", len(changes.Create)),
		zap.Int("updateOld", len(changes.UpdateOld)),
		zap.Int("updateNew", len(changes.UpdateNew)),
		zap.Int("delete", len(changes.Delete)))

	// Validate input before proceeding
	if len(changes.UpdateOld) != len(changes.UpdateNew) {
		p.logger.Error("Update slices have different lengths",
			zap.Int("updateOld", len(changes.UpdateOld)),
			zap.Int("updateNew", len(changes.UpdateNew)))
		return ErrUpdateSlicesMismatch
	}

	// Check if there are any changes to apply
	if len(changes.Create) == 0 && len(changes.UpdateNew) == 0 && len(changes.Delete) == 0 {
		p.logger.Info("No changes to apply")
		return nil
	}

	// Ensure we have domains selected
	domains, err := p.SelectDomains()
	if err != nil {
		p.logger.Error("Failed to select domains", zap.Error(err))
		return err
	}

	p.logger.Debug("Selected domains for ApplyChangesWithWorkers method",
		zap.Int("count", len(domains)))

	// Build tasks for all changes, routing each endpoint to its domain
	var tasks []changeTask

	addTask := func(action string, ep, oldEp *endpoint.Endpoint) {
		domain, ok := domainForEndpoint(domains, ep.DNSName)
		if !ok {
			p.logger.Error("Endpoint does not belong to any selected domain, skipping",
				zap.String("action", action),
				zap.String("dnsName", ep.DNSName),
				zap.String("recordType", ep.RecordType))
			return
		}
		tasks = append(tasks, changeTask{action: action, change: ep, oldChange: oldEp, domain: domain})
	}

	// Add creation tasks
	for _, endpoint := range changes.Create {
		addTask(CREATE, endpoint, nil)
	}

	// Add update tasks
	for i, endpoint := range changes.UpdateNew {
		addTask(UPDATE, endpoint, changes.UpdateOld[i])
	}

	// Add deletion tasks
	for _, endpoint := range changes.Delete {
		addTask(DELETE, endpoint, nil)
	}

	// Process all tasks with workers
	return p.processTasksWithWorkers(ctx, tasks)
}

// domainForEndpoint returns the selected domain responsible for the given DNS
// name, preferring the longest matching domain suffix. If the name matches
// none of the selected domains but exactly one domain is selected, that
// domain is used as a fallback so short (non-FQDN) names keep working.
func domainForEndpoint(domains []myrasec.Domain, dnsName string) (myrasec.Domain, bool) {
	name := normalizeDomainName(dnsName)

	var best myrasec.Domain
	bestLen := -1
	for _, domain := range domains {
		domainName := normalizeDomainName(domain.Name)
		if (name == domainName || strings.HasSuffix(name, "."+domainName)) && len(domainName) > bestLen {
			best = domain
			bestLen = len(domainName)
		}
	}
	if bestLen >= 0 {
		return best, true
	}

	if len(domains) == 1 {
		return domains[0], true
	}

	return myrasec.Domain{}, false
}

// processTasksWithWorkers processes DNS record tasks using multiple worker goroutines.
func (p *MyraSecDNSProvider) processTasksWithWorkers(ctx context.Context, tasks []changeTask) error {
	if len(tasks) == 0 {
		return nil
	}

	// Use configured worker count or default to 4
	workerCount := 4
	if len(tasks) < workerCount {
		workerCount = len(tasks) // Don't create more workers than tasks
	}

	// Create channels for tasks and errors
	taskChan := make(chan changeTask, len(tasks))
	resultChan := make(chan error, len(tasks))

	// Create a context that can be canceled
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // Ensure all resources are cleaned up

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			p.worker(ctx, workerID, taskChan, resultChan)
		}(i)
	}

	// Send tasks to workers
	go func() {
		for _, task := range tasks {
			select {
			case taskChan <- task:
				// Task sent successfully
			case <-ctx.Done():
				// Context was canceled, stop sending tasks
				return
			}
		}
		close(taskChan) // Signal that no more tasks will be sent
	}()

	// Collect results and capture first error
	var firstErr error
collect:
	for i := 0; i < len(tasks); i++ {
		select {
		case err := <-resultChan:
			if err != nil && firstErr == nil {
				firstErr = err
				cancel() // Cancel context to stop other workers
			}
		case <-ctx.Done():
			// Context was canceled externally; stop collecting. Workers cannot
			// block on send since resultChan is buffered to len(tasks).
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			break collect
		}
	}

	// Wait for all workers to finish
	wg.Wait()
	close(resultChan)

	return firstErr
}

// worker is a goroutine that processes tasks from the task channel
func (p *MyraSecDNSProvider) worker(ctx context.Context, id int, taskChan <-chan changeTask, resultChan chan<- error) {
	for {
		select {
		case task, ok := <-taskChan:
			if !ok {
				// Channel closed, no more tasks
				return
			}

			// Skip actual API calls in dry-run mode
			if p.dryRun {
				p.logger.Info("Would process DNS record (dry-run)",
					zap.Int("worker", id),
					zap.String("action", task.action),
					zap.String("name", task.change.DNSName),
					zap.String("type", task.change.RecordType))
				resultChan <- nil
				continue
			}

			// Process the task based on action type
			var err error
			switch task.action {
			case CREATE:
				err = p.processCreateActions(task.domain, []*endpoint.Endpoint{task.change})
			case UPDATE:
				err = p.processUpdateActions(task.domain, []*endpoint.Endpoint{task.oldChange}, []*endpoint.Endpoint{task.change})
			case DELETE:
				err = p.processDeleteActions(task.domain, []*endpoint.Endpoint{task.change})
			default:
				err = fmt.Errorf("unknown action: %s", task.action)
			}

			resultChan <- err

		case <-ctx.Done():
			return
		}
	}
}
