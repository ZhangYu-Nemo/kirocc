package reqconv

import (
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"sort"
	"strconv"
)

// unsupportedKeywords lists JSON Schema keywords that Kiro API rejects.
var unsupportedKeywords = map[string]struct{}{
	"additionalProperties":  {},
	"$schema":               {},
	"propertyNames":         {},
	"default":               {},
	"exclusiveMinimum":      {},
	"exclusiveMaximum":      {},
	"$defs":                 {},
	"$ref":                  {},
	"patternProperties":     {},
	"if":                    {},
	"then":                  {},
	"else":                  {},
	"dependentRequired":     {},
	"dependentSchemas":      {},
	"prefixItems":           {},
	"unevaluatedProperties": {},
	"unevaluatedItems":      {},
	"contentMediaType":      {},
	"contentEncoding":       {},
	"format":                {},
	"pattern":               {},
	"minLength":             {},
	"maxLength":             {},
	"minimum":               {},
	"maximum":               {},
	"minItems":              {},
	"maxItems":              {},
	"uniqueItems":           {},
	"multipleOf":            {},
	"not":                   {},
}

// SanitizeJSONSchema recursively removes fields that Kiro API rejects.
func SanitizeJSONSchema(schema map[string]any) map[string]any {
	return sanitizeJSONSchema(schema, "")
}

func sanitizeJSONSchema(schema map[string]any, toolName string) map[string]any {
	return sanitizeJSONSchemaAtPath(schema, toolName, "")
}

func sanitizeJSONSchemaAtPath(schema map[string]any, toolName, schemaPath string) map[string]any {
	if schema == nil {
		return map[string]any{}
	}

	result := make(map[string]any, len(schema))

	// First pass: process all non-combinator keys.
	for key, value := range schema {
		if _, drop := unsupportedKeywords[key]; drop {
			continue
		}
		switch key {
		case "const":
			result["enum"] = []any{value}
		case "required":
			if arr, ok := value.([]any); ok && len(arr) == 0 {
				continue
			}
			result[key] = value
		case "anyOf", "oneOf", "allOf":
			// Handled in second pass.
		default:
			switch v := value.(type) {
			case map[string]any:
				result[key] = sanitizeJSONSchemaAtPath(v, toolName, appendSchemaPath(schemaPath, key))
			case []any:
				sanitized := make([]any, len(v))
				for i, item := range v {
					if m, ok := item.(map[string]any); ok {
						sanitized[i] = sanitizeJSONSchemaAtPath(m, toolName, appendSchemaPath(schemaPath, key))
					} else {
						sanitized[i] = item
					}
				}
				result[key] = sanitized
			default:
				result[key] = value
			}
		}
	}

	// Second pass: apply combinators last so they deterministically override.
	for key, value := range schema {
		switch key {
		case "anyOf", "oneOf":
			if arr, ok := value.([]any); ok && len(arr) > 0 {
				branches := sanitizeCombinatorBranches(arr, toolName, schemaPath)
				if selected, ok := selectArtifactBranch(toolName, schemaPath, branches); ok {
					maps.Copy(result, selected)
					continue
				}
				if merged := flattenEnumBranches(branches); merged != nil {
					maps.Copy(result, merged)
					continue
				}

				nonNull := dropNullBranches(branches)
				if len(nonNull) == 1 {
					maps.Copy(result, nonNull[0])
					continue
				}
				if len(nonNull) > 0 {
					collapsed := collapseEquivalentBranches(nonNull)
					if len(collapsed) == 1 {
						maps.Copy(result, collapsed[0])
						continue
					}
					slog.Debug("lossy schema conversion details",
						"combinator", key,
						"tool_name", toolName,
						"validation_diff_paths", validationDiffPaths(nonNull))
					slog.Warn("lossy schema conversion: using first branch only",
						"combinator", key, "branches", len(arr), "tool_name", toolName)
					maps.Copy(result, nonNull[0])
					continue
				}
				if len(branches) > 0 {
					slog.Warn("lossy schema conversion: using first branch only",
						"combinator", key, "branches", len(arr), "tool_name", toolName)
					maps.Copy(result, branches[0])
				}
			}
		case "allOf":
			if arr, ok := value.([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						maps.Copy(result, sanitizeJSONSchemaAtPath(m, toolName, schemaPath))
					}
				}
			}
		}
	}

	return result
}

// EnsureObjectRoot wraps a sanitized schema in an object envelope if its root
// type is not "object". Call this on the final schema passed to Kiro, not during
// recursive sanitization of nested properties.
//
// Kiro/Bedrock rejects any tool whose inputSchema.json.type is not "object":
//
//	ValidationException: The value at toolConfig.tools.0.toolSpec.inputSchema.json.type
//	must be one of the following: object. reason: TOOL_SCHEMA_INVALID
//
// Anthropic's API has no such constraint, so clients (including Claude Code's
// built-in tools like WebSearch) may send schemas with type:"string" or no type
// at all. This wrapper satisfies the validation without altering semantics for
// the model.
func EnsureObjectRoot(schema map[string]any) map[string]any {
	if len(schema) == 0 {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	t, _ := schema["type"].(string)
	if t == "object" {
		return schema
	}
	if t == "" {
		// No type declared — add it rather than wrapping.
		schema["type"] = "object"
		return schema
	}
	// Non-object type: wrap in an object envelope.
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"input": schema,
		},
	}
}

func sanitizeCombinatorBranches(branches []any, toolName, schemaPath string) []map[string]any {
	result := make([]map[string]any, 0, len(branches))
	for _, branch := range branches {
		m, ok := branch.(map[string]any)
		if ok {
			result = append(result, sanitizeJSONSchemaAtPath(m, toolName, schemaPath))
		}
	}
	return result
}

func appendSchemaPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func selectArtifactBranch(toolName, schemaPath string, branches []map[string]any) (map[string]any, bool) {
	if toolName != "Artifact" || len(branches) != 2 {
		return nil, false
	}

	switch schemaPath {
	case "properties.contract":
		var broadString map[string]any
		for _, branch := range branches {
			if branch["type"] != "string" {
				return nil, false
			}
			if _, hasEnum := branch["enum"]; hasEnum {
				continue
			}
			if broadString != nil {
				return nil, false
			}
			broadString = branch
		}
		if broadString != nil {
			return broadString, true
		}
	case "properties.files":
		for _, branch := range branches {
			if branch["type"] == "object" {
				return branch, true
			}
		}
	}

	return nil, false
}

// dropNullBranches returns branches that are not {type: "null"}.
func dropNullBranches(branches []map[string]any) []map[string]any {
	result := make([]map[string]any, 0, len(branches))
	for _, branch := range branches {
		if branch["type"] != "null" {
			result = append(result, branch)
		}
	}
	return result
}

// flattenEnumBranches merges anyOf/oneOf branches when all branches have enum values.
// Returns a merged schema with combined enum, or nil if not all branches are enum-based.
func flattenEnumBranches(branches []map[string]any) map[string]any {
	if len(branches) == 0 {
		return nil
	}
	var allEnums []any
	var typ string
	typConsistent := true
	for _, branch := range branches {
		enumVal, hasEnum := branch["enum"]
		if !hasEnum {
			return nil
		}
		arr, ok := enumVal.([]any)
		if !ok {
			return nil
		}
		allEnums = append(allEnums, arr...)
		if t, ok := branch["type"].(string); ok {
			if typ == "" {
				typ = t
			} else if typ != t {
				typConsistent = false
			}
		} else {
			typConsistent = false
		}
	}
	merged := map[string]any{"enum": allEnums}
	if typ != "" && typConsistent {
		merged["type"] = typ
	}
	return merged
}

var ignoredValidationKeywords = map[string]struct{}{
	"$comment":    {},
	"deprecated":  {},
	"description": {},
	"examples":    {},
	"readOnly":    {},
	"title":       {},
	"writeOnly":   {},
}

func collapseEquivalentBranches(branches []map[string]any) []map[string]any {
	result := make([]map[string]any, 0, len(branches))
	shapes := make([]any, 0, len(branches))
	for _, branch := range branches {
		shape := validationShape(branch)
		duplicate := false
		for _, existing := range shapes {
			if reflect.DeepEqual(shape, existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, branch)
			shapes = append(shapes, shape)
		}
	}
	return result
}

const maxValidationDiffPaths = 8

func validationDiffPaths(branches []map[string]any) []string {
	if len(branches) < 2 {
		return nil
	}

	paths := make([]string, 0, maxValidationDiffPaths)
	seen := make(map[string]struct{}, maxValidationDiffPaths)
	left := validationShape(branches[0])
	for index := 1; index < len(branches) && len(paths) < maxValidationDiffPaths; index++ {
		collectValidationDiffPaths("", left, validationShape(branches[index]), &paths, seen)
	}
	return paths
}

func collectValidationDiffPaths(path string, left, right any, paths *[]string, seen map[string]struct{}) {
	if len(*paths) >= maxValidationDiffPaths {
		return
	}

	leftMap, leftIsMap := left.(map[string]any)
	rightMap, rightIsMap := right.(map[string]any)
	if leftIsMap || rightIsMap {
		if !leftIsMap || !rightIsMap {
			addValidationDiffPath(paths, seen, validationDiff(path, left, right))
			return
		}

		keys := make([]string, 0, len(leftMap)+len(rightMap))
		keySet := make(map[string]struct{}, len(leftMap)+len(rightMap))
		for key := range leftMap {
			keySet[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range rightMap {
			if _, ok := keySet[key]; !ok {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			leftValue, leftOK := leftMap[key]
			rightValue, rightOK := rightMap[key]
			if !leftOK || !rightOK {
				addValidationDiffPath(paths, seen, childPath+" (branch key missing)")
				continue
			}
			collectValidationDiffPaths(childPath, leftValue, rightValue, paths, seen)
			if len(*paths) >= maxValidationDiffPaths {
				return
			}
		}
		return
	}

	leftSlice, leftIsSlice := left.([]any)
	rightSlice, rightIsSlice := right.([]any)
	if leftIsSlice || rightIsSlice {
		if !leftIsSlice || !rightIsSlice {
			addValidationDiffPath(paths, seen, validationDiff(path, left, right))
			return
		}
		if len(leftSlice) != len(rightSlice) {
			addValidationDiffPath(paths, seen, fmt.Sprintf("%s.length=%d != %d", path, len(leftSlice), len(rightSlice)))
		}
		for index := 0; index < len(leftSlice) && index < len(rightSlice); index++ {
			collectValidationDiffPaths(path+"["+strconv.Itoa(index)+"]", leftSlice[index], rightSlice[index], paths, seen)
			if len(*paths) >= maxValidationDiffPaths {
				return
			}
		}
		return
	}

	if !reflect.DeepEqual(left, right) {
		addValidationDiffPath(paths, seen, validationDiff(path, left, right))
	}
}

func addValidationDiffPath(paths *[]string, seen map[string]struct{}, path string) {
	if _, ok := seen[path]; ok {
		return
	}
	seen[path] = struct{}{}
	if len(*paths) < maxValidationDiffPaths {
		*paths = append(*paths, path)
	}
}

func validationDiff(path string, left, right any) string {
	return path + "=" + compactValidationValue(left) + " != " + compactValidationValue(right)
}

func compactValidationValue(value any) string {
	if value == nil {
		return "null"
	}
	if text, ok := value.(string); ok {
		return strconv.Quote(text)
	}
	text := fmt.Sprintf("%v", value)
	if len(text) > 48 {
		return text[:45] + "..."
	}
	return text
}

func validationShape(value any) any {
	switch v := value.(type) {
	case map[string]any:
		shape := make(map[string]any, len(v))
		for key, nested := range v {
			if _, ignored := ignoredValidationKeywords[key]; ignored {
				continue
			}
			shape[key] = validationShape(nested)
		}
		return shape
	case []any:
		shape := make([]any, len(v))
		for i, nested := range v {
			shape[i] = validationShape(nested)
		}
		return shape
	default:
		return value
	}
}
