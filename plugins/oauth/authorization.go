package oauth

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/centralmind/gateway/errors"
	"golang.org/x/xerrors"
)

// evaluateClaimRule checks if the claim value matches the rule
func evaluateClaimRule(rule ClaimRule, claims map[string]interface{}, params map[string]interface{}) (bool, error) {
	// Get claim value by path
	value, ok := getClaimValue(claims, rule.Claim)
	if !ok {
		// If claim doesn't exist
		if rule.Operation == "exists" {
			return false, nil
		}
		return false, nil
	}

	// If operation only checks existence
	if rule.Operation == "exists" {
		return true, nil
	}

	// Process template in rule value
	tmpl, err := template.New("rule").Parse(rule.Value)
	if err != nil {
		return false, xerrors.Errorf("invalid rule template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return false, xerrors.Errorf("failed to execute template: %w", err)
	}
	expectedValue := buf.String()

	// Check value based on operation
	switch rule.Operation {
	case "eq":
		return compareEqual(value, expectedValue), nil
	case "ne":
		return !compareEqual(value, expectedValue), nil
	case "contains":
		return containsValue(value, expectedValue), nil
	case "regex":
		return matchRegex(value, expectedValue)
	default:
		return false, xerrors.Errorf("unsupported operation: %s", rule.Operation)
	}
}

// getClaimValue retrieves a value from claims by path (supports nesting via dots and array indices)
func getClaimValue(claims map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	current := claims

	for i, part := range parts {
		// Check for array access
		if idx := strings.Index(part, "["); idx != -1 {
			arrayName := part[:idx]
			indexStr := part[idx+1 : len(part)-1]

			// Get array
			array, ok := current[arrayName].([]interface{})
			if !ok {
				return nil, false
			}

			// Validate index
			index := 0
			_, err := fmt.Sscanf(indexStr, "%d", &index)
			if err != nil || index < 0 || index >= len(array) {
				return nil, false
			}

			if i == len(parts)-1 {
				return array[index], true
			}

			// If not the last part, continue navigation
			if next, ok := array[index].(map[string]interface{}); ok {
				current = next
			} else {
				return nil, false
			}
			continue
		}

		// Regular field
		if i == len(parts)-1 {
			val, ok := current[part]
			return val, ok
		}

		next, ok := current[part].(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = next
	}

	return nil, false
}

// compareEqual compares two values for equality
func compareEqual(actual interface{}, expected string) bool {
	switch v := actual.(type) {
	case string:
		return v == expected
	case bool:
		return strings.ToLower(expected) == strconv.FormatBool(v)
	case float64:
		expectedFloat, err := strconv.ParseFloat(expected, 64)
		if err != nil {
			return false
		}
		return v == expectedFloat
	case int:
		expectedInt, err := strconv.Atoi(expected)
		if err != nil {
			return false
		}
		return v == expectedInt
	default:
		return fmt.Sprintf("%v", actual) == expected
	}
}

// containsValue checks if an array contains a value
func containsValue(actual interface{}, expected string) bool {
	switch v := actual.(type) {
	case []interface{}:
		for _, item := range v {
			if compareEqual(item, expected) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

// matchRegex checks if a value matches a regular expression
func matchRegex(actual interface{}, pattern string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, xerrors.Errorf("invalid regex pattern: %w", err)
	}

	str := fmt.Sprintf("%v", actual)
	return re.MatchString(str), nil
}

// checkAuthorization verifies authorization for a method
func (c *Connector) checkAuthorization(method string, claims map[string]interface{}, params map[string]interface{}) error {
	// no rules == not authorization, only authentication
	if len(c.config.AuthorizationRules) == 0 {
		return nil
	}
	// Check rules for the method
	var applicableRules []AuthorizationRule
	for _, rule := range c.config.AuthorizationRules {
		if contains(rule.Methods, method) {
			applicableRules = append(applicableRules, rule)
		}
	}
	if len(applicableRules) == 0 {
		for _, rule := range c.config.AuthorizationRules {
			if len(rule.Methods) == 1 && rule.Methods[0] == "*" {
				// wildcard match
				applicableRules = append(applicableRules, rule)
			}
		}
	}
	for _, rule := range applicableRules {
		// If method is public, allow access
		if rule.AllowPublic {
			return nil
		}

		// Check all claim rules
		matches := 0
		for _, claimRule := range rule.ClaimRules {
			ok, err := evaluateClaimRule(claimRule, claims, params)
			if err != nil {
				return xerrors.Errorf("failed to evaluate claim rule: %w", err)
			}
			if ok {
				matches++
				// If not requiring all rules, one match is sufficient
				if !rule.RequireAllClaims {
					return nil
				}
			}
		}

		// If requiring all rules and all matched
		if rule.RequireAllClaims && matches == len(rule.ClaimRules) {
			return nil
		}
	}

	return errors.ErrNotAuthorized
}

// contains checks if a slice contains an item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
