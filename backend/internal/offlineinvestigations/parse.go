package offlineinvestigations

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	EvidenceEntraSignIns              = "entra_sign_ins"
	EvidenceEntraDirectoryAudit       = "entra_directory_audits"
	EvidenceM365Activity              = "m365_activity"
	MaxFileSize                 int64 = 1 << 30
	MaxRecordsPerFile                 = 10_000_000
)

var ErrUnsupportedEvidence = errors.New("unsupported evidence format")

type ParsedFile struct {
	EvidenceType string
	Records      []json.RawMessage
	Fields       []string
}

func ParseFile(name, mediaType string, content []byte) (ParsedFile, error) {
	if len(content) == 0 {
		return ParsedFile{}, errors.New("evidence file is empty")
	}
	if int64(len(content)) > MaxFileSize {
		return ParsedFile{}, fmt.Errorf("evidence file exceeds the %d GiB limit", MaxFileSize>>30)
	}
	if !utf8.Valid(content) {
		return ParsedFile{}, errors.New("evidence file must be UTF-8 JSON or CSV")
	}
	ext := strings.ToLower(filepath.Ext(name))
	var records []json.RawMessage
	var err error
	if ext == ".csv" || strings.Contains(strings.ToLower(mediaType), "csv") {
		records, err = decodeCSV(content)
	} else if ext == ".json" || ext == ".jsonl" || ext == ".ndjson" || strings.Contains(strings.ToLower(mediaType), "json") || json.Valid(content) {
		records, err = decodeJSONRecords(content)
	} else {
		return ParsedFile{}, ErrUnsupportedEvidence
	}
	if err != nil {
		return ParsedFile{}, err
	}
	if len(records) == 0 {
		return ParsedFile{}, errors.New("evidence file contains no records")
	}
	if len(records) > MaxRecordsPerFile {
		return ParsedFile{}, fmt.Errorf("evidence file exceeds the %d record limit", MaxRecordsPerFile)
	}
	evidenceType, fields, err := classifyRecords(records)
	if err != nil {
		return ParsedFile{}, err
	}
	return ParsedFile{EvidenceType: evidenceType, Records: records, Fields: fields}, nil
}

func decodeJSONRecords(content []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, errors.New("evidence file is empty")
	}
	if trimmed[0] == '[' {
		var records []json.RawMessage
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
		return records, nil
	}
	if trimmed[0] == '{' {
		var envelope struct {
			Value []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err == nil && envelope.Value != nil {
			return envelope.Value, nil
		}
		if json.Valid(trimmed) {
			return []json.RawMessage{append([]byte(nil), trimmed...)}, nil
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var records []json.RawMessage
	for {
		var record json.RawMessage
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse newline-delimited JSON: %w", err)
		}
		records = append(records, append([]byte(nil), record...))
	}
	return records, nil
}

func decodeCSV(content []byte) ([]json.RawMessage, error) {
	reader := csv.NewReader(bytes.NewReader(content))
	reader.FieldsPerRecord = -1
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read CSV headers: %w", err)
	}
	for i := range headers {
		headers[i] = canonicalHeader(strings.TrimPrefix(headers[i], "\ufeff"))
	}
	var records []json.RawMessage
	for rowNumber := 2; ; rowNumber++ {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read CSV row %d: %w", rowNumber, err)
		}
		record := map[string]any{}
		for index, value := range row {
			if index >= len(headers) || headers[index] == "" {
				continue
			}
			assignCSVValue(record, headers[index], strings.TrimSpace(value))
		}
		record, err = unwrapPurviewAuditData(record)
		if err != nil {
			return nil, fmt.Errorf("read CSV row %d: %w", rowNumber, err)
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		records = append(records, raw)
	}
	return records, nil
}

func canonicalHeader(value string) string {
	normalized := normalizeField(value)
	if canonical := map[string]string{
		"id": "id", "createddatetime": "createdDateTime", "userprincipalname": "userPrincipalName",
		"userdisplayname": "userDisplayName", "userid": "userId", "ipaddress": "ipAddress",
		"resourcedisplayname": "resourceDisplayName", "appdisplayname": "appDisplayName",
		"resourceid": "resourceId", "appid": "appId", "authenticationrequirement": "authenticationRequirement",
		"authenticationdetails": "authenticationDetails", "authenticationmethodsused": "authenticationMethodsUsed",
		"conditionalaccessstatus": "conditionalAccessStatus", "isinteractive": "isInteractive",
		"activitydatetime": "activityDateTime", "activitydisplayname": "activityDisplayName",
		"operationtype": "operationType", "result": "result", "initiatedby": "initiatedBy",
		"targetresources": "targetResources", "creationtime": "CreationTime", "workload": "Workload",
		"operation": "Operation", "clientip": "ClientIP", "objectid": "ObjectId", "resultstatus": "ResultStatus",
		"recordid": "RecordId", "creationdate": "CreationDate", "recordtype": "RecordType", "auditdata": "AuditData",
		"associatedadminunits": "AssociatedAdminUnits", "associatedadminunitsnames": "AssociatedAdminUnitsNames",
		"statuserrorcode": "status.errorCode",
	}[normalized]; canonical != "" {
		return canonical
	}
	return strings.TrimSpace(value)
}

// Purview audit search exports wrap each complete Management Activity record
// as JSON in an AuditData CSV column. Unwrap that provider-native shape while
// retaining wrapper metadata and backfilling the few equivalent outer fields.
func unwrapPurviewAuditData(record map[string]any) (map[string]any, error) {
	value, wrapped := record["AuditData"]
	if !wrapped {
		return record, nil
	}
	audit, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("AuditData must contain a JSON object")
	}
	for key, value := range record {
		if key == "AuditData" {
			continue
		}
		if _, exists := audit[key]; !exists {
			audit[key] = value
		}
	}
	for outer, inner := range map[string]string{
		"RecordId": "Id", "CreationDate": "CreationTime",
		"Operation": "Operation", "UserId": "UserId", "RecordType": "RecordType",
	} {
		if _, exists := audit[inner]; exists {
			continue
		}
		if value, exists := record[outer]; exists {
			audit[inner] = value
		}
	}
	return audit, nil
}

func assignCSVValue(record map[string]any, key, value string) {
	var decoded any = value
	if value != "" && (strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{")) {
		var candidate any
		if json.Unmarshal([]byte(value), &candidate) == nil {
			decoded = candidate
		}
	} else if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		boolean, _ := strconv.ParseBool(value)
		decoded = boolean
	}
	if strings.Contains(key, ".") {
		parts := strings.SplitN(key, ".", 2)
		nested, _ := record[parts[0]].(map[string]any)
		if nested == nil {
			nested = map[string]any{}
			record[parts[0]] = nested
		}
		nested[parts[1]] = decoded
		return
	}
	record[key] = decoded
}

func classifyRecords(records []json.RawMessage) (string, []string, error) {
	allFields := map[string]struct{}{}
	evidenceType := ""
	for index, raw := range records {
		var record map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&record); err != nil {
			return "", nil, fmt.Errorf("record %d is not a JSON object", index+1)
		}
		for key := range record {
			allFields[normalizeField(key)] = struct{}{}
		}
		kind := classifyRecord(record)
		if kind == "" {
			return "", nil, fmt.Errorf("record %d does not match a supported Graph sign-in, Graph directory audit, or Microsoft 365 activity export", index+1)
		}
		if evidenceType == "" {
			evidenceType = kind
		} else if evidenceType != kind {
			return "", nil, errors.New("one evidence file cannot mix different export types")
		}
	}
	fields := make([]string, 0, len(allFields))
	for field := range allFields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return evidenceType, fields, nil
}

func classifyRecord(record map[string]any) string {
	fields := map[string]bool{}
	for key := range record {
		fields[normalizeField(key)] = true
	}
	if fields["createddatetime"] && (fields["userprincipalname"] || fields["ipaddress"] || fields["authenticationrequirement"]) {
		return EvidenceEntraSignIns
	}
	if fields["activitydatetime"] && (fields["activitydisplayname"] || fields["targetresources"]) {
		return EvidenceEntraDirectoryAudit
	}
	if fields["creationtime"] && fields["operation"] && fields["workload"] {
		return EvidenceM365Activity
	}
	return ""
}

func normalizeField(value string) string {
	var normalized strings.Builder
	for _, character := range strings.ToLower(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			normalized.WriteRune(character)
		}
	}
	return normalized.String()
}
