package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// DefenseRecord represents a validated defense stored on the ledger.
type DefenseRecord struct {
	IncidentID        string           `json:"incidentId"`
	AttackType        string           `json:"attackType"`
	MitreTechnique    string           `json:"mitreTechnique"`
	SourceIP          string           `json:"sourceIp"`
	TargetSystem      string           `json:"targetSystem"`
	RiskScore         string           `json:"riskScore"`
	AgentConfidence   string           `json:"agentConfidence"`
	EvidenceHash      string           `json:"evidenceHash"`
	DefenseRule       string           `json:"defenseRule"`
	ValidationStatus  string           `json:"validationStatus"`
	LifecycleStatus   string           `json:"lifecycleStatus"`
	OwnerOrgMSP       string           `json:"ownerOrgMsp"`
	AllowedOrgs       []string         `json:"allowedOrgs"`
	AllowedRoles      []string         `json:"allowedRoles"`
	RequiredApprovals []string         `json:"requiredApprovals"`
	Approvals         []ApprovalRecord `json:"approvals"`
	LastUpdatedAt     string           `json:"lastUpdatedAt"`
	Timestamp         string           `json:"timestamp"`
}

// ApprovalRecord captures multi-organization approval evidence.
type ApprovalRecord struct {
	OrgMSP    string `json:"orgMsp"`
	Role      string `json:"role"`
	TxID      string `json:"txId"`
	Timestamp string `json:"timestamp"`
}

// DefenseAuditEvent captures one historical ledger state.
type DefenseAuditEvent struct {
	TxID      string         `json:"txId"`
	Timestamp string         `json:"timestamp"`
	IsDelete  bool           `json:"isDelete"`
	Record    *DefenseRecord `json:"record,omitempty"`
}

// DefenseRegistryContract implements the chaincode interface.
type DefenseRegistryContract struct {
	contractapi.Contract
}

// RegisterDefense creates a new defense record on the ledger.
func (c *DefenseRegistryContract) RegisterDefense(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
	attackType string,
	mitreTechnique string,
	sourceIP string,
	targetSystem string,
	riskScore string,
	agentConfidence string,
	evidenceHash string,
	defenseRule string,
	validationStatus string,
	timestamp string,
	ownerOrgMSP string,
	allowedOrgsJSON string,
	allowedRolesJSON string,
	requiredApprovalsJSON string,
) error {
	existing, err := ctx.GetStub().GetState(incidentId)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("defense record %s already exists", incidentId)
	}

	allowedOrgs, err := parseJSONArray(allowedOrgsJSON)
	if err != nil {
		return fmt.Errorf("failed to parse allowed organizations: %v", err)
	}

	allowedRoles, err := parseJSONArray(allowedRolesJSON)
	if err != nil {
		return fmt.Errorf("failed to parse allowed roles: %v", err)
	}

	requiredApprovals, err := parseJSONArray(requiredApprovalsJSON)
	if err != nil {
		return fmt.Errorf("failed to parse required approvals: %v", err)
	}

	ownerOrgMSP = strings.TrimSpace(ownerOrgMSP)
	if ownerOrgMSP == "" {
		clientOrg, orgErr := ctx.GetClientIdentity().GetMSPID()
		if orgErr != nil {
			return fmt.Errorf("failed to resolve owner org MSP: %v", orgErr)
		}
		ownerOrgMSP = clientOrg
	}

	allowedOrgs = dedupeAndSort(append(allowedOrgs, ownerOrgMSP))
	allowedRoles = dedupeAndSort(allowedRoles)
	requiredApprovals = dedupeAndSort(requiredApprovals)

	record := DefenseRecord{
		IncidentID:        incidentId,
		AttackType:        attackType,
		MitreTechnique:    mitreTechnique,
		SourceIP:          sourceIP,
		TargetSystem:      targetSystem,
		RiskScore:         riskScore,
		AgentConfidence:   agentConfidence,
		EvidenceHash:      evidenceHash,
		DefenseRule:       defenseRule,
		ValidationStatus:  validationStatus,
		LifecycleStatus:   "VALIDATED",
		OwnerOrgMSP:       ownerOrgMSP,
		AllowedOrgs:       allowedOrgs,
		AllowedRoles:      allowedRoles,
		RequiredApprovals: requiredApprovals,
		Approvals:         []ApprovalRecord{},
		LastUpdatedAt:     timestamp,
		Timestamp:         timestamp,
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal defense record: %v", err)
	}

	return ctx.GetStub().PutState(incidentId, recordJSON)
}

// GetDefense reads a single defense record from the ledger.
func (c *DefenseRegistryContract) GetDefense(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
) (*DefenseRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(incidentId)
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("defense record %s does not exist", incidentId)
	}

	var record DefenseRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal defense record: %v", err)
	}

	if err := enforceRecordReadAccess(ctx, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

// UpdateDefenseStatus changes the lifecycle status of a defense record.
func (c *DefenseRegistryContract) UpdateDefenseStatus(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
	newStatus string,
) error {
	recordJSON, err := ctx.GetStub().GetState(incidentId)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if recordJSON == nil {
		return fmt.Errorf("defense record %s does not exist", incidentId)
	}

	var record DefenseRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		return fmt.Errorf("failed to unmarshal defense record: %v", err)
	}

	clientOrg, clientRole, err := resolveClientIdentity(ctx)
	if err != nil {
		return err
	}

	if !hasRole(clientRole, []string{"responder", "admin"}) {
		return fmt.Errorf("access denied: role %s cannot update lifecycle status", clientRole)
	}

	if !containsValue(record.AllowedOrgs, clientOrg) {
		return fmt.Errorf("access denied: org %s is not allowed", clientOrg)
	}

	newStatus = strings.TrimSpace(strings.ToUpper(newStatus))
	if newStatus == "" {
		return fmt.Errorf("new lifecycle status cannot be empty")
	}

	if newStatus == "CLOSED" && !hasRequiredApprovals(record.RequiredApprovals, record.Approvals) {
		return fmt.Errorf("cannot close incident %s before all required approvals are collected", incidentId)
	}

	record.LifecycleStatus = newStatus
	record.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)

	updatedJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated record: %v", err)
	}

	return ctx.GetStub().PutState(incidentId, updatedJSON)
}

// ApproveDefenseClosure collects multi-organization closure approvals.
func (c *DefenseRegistryContract) ApproveDefenseClosure(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
	timestamp string,
) error {
	record, err := loadDefenseRecord(ctx, incidentId)
	if err != nil {
		return err
	}

	clientOrg, clientRole, err := resolveClientIdentity(ctx)
	if err != nil {
		return err
	}

	if !containsValue(record.RequiredApprovals, clientOrg) {
		return fmt.Errorf("org %s is not a required approver", clientOrg)
	}

	if !hasRole(clientRole, []string{"auditor", "admin", "responder"}) {
		return fmt.Errorf("role %s is not allowed to approve closure", clientRole)
	}

	for _, existing := range record.Approvals {
		if strings.EqualFold(existing.OrgMSP, clientOrg) {
			return fmt.Errorf("org %s has already approved closure", clientOrg)
		}
	}

	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	record.Approvals = append(record.Approvals, ApprovalRecord{
		OrgMSP:    clientOrg,
		Role:      clientRole,
		TxID:      ctx.GetStub().GetTxID(),
		Timestamp: timestamp,
	})
	record.LastUpdatedAt = timestamp

	return saveDefenseRecord(ctx, record)
}

// AnchorPrivateEvidence stores sensitive evidence metadata in a private collection.
func (c *DefenseRegistryContract) AnchorPrivateEvidence(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
	collectionName string,
	evidenceMetadataJSON string,
) error {
	record, err := loadDefenseRecord(ctx, incidentId)
	if err != nil {
		return err
	}

	if err := enforceRecordReadAccess(ctx, record); err != nil {
		return err
	}

	collectionName = strings.TrimSpace(collectionName)
	if collectionName == "" {
		return fmt.Errorf("collection name is required")
	}

	if strings.TrimSpace(evidenceMetadataJSON) == "" {
		return fmt.Errorf("private evidence metadata cannot be empty")
	}

	return ctx.GetStub().PutPrivateData(collectionName, incidentId, []byte(evidenceMetadataJSON))
}

// GetPrivateEvidence returns sensitive evidence metadata from a private collection.
func (c *DefenseRegistryContract) GetPrivateEvidence(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
	collectionName string,
) (string, error) {
	record, err := loadDefenseRecord(ctx, incidentId)
	if err != nil {
		return "", err
	}

	if err := enforceRecordReadAccess(ctx, record); err != nil {
		return "", err
	}

	collectionName = strings.TrimSpace(collectionName)
	if collectionName == "" {
		return "", fmt.Errorf("collection name is required")
	}

	data, err := ctx.GetStub().GetPrivateData(collectionName, incidentId)
	if err != nil {
		return "", fmt.Errorf("failed to read private evidence: %v", err)
	}
	if data == nil {
		return "", fmt.Errorf("private evidence for %s does not exist", incidentId)
	}

	return string(data), nil
}

// GetAllDefenses returns all defense records from the ledger.
func (c *DefenseRegistryContract) GetAllDefenses(
	ctx contractapi.TransactionContextInterface,
) ([]*DefenseRecord, error) {
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger range: %v", err)
	}
	defer iterator.Close()

	var records []*DefenseRecord

	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate ledger: %v", err)
		}

		var record DefenseRecord
		err = json.Unmarshal(result.Value, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record: %v", err)
		}

		if accessErr := enforceRecordReadAccess(ctx, &record); accessErr != nil {
			continue
		}

		records = append(records, &record)
	}

	return records, nil
}

// GetDefenseHistory returns immutable audit history for one incident.
func (c *DefenseRegistryContract) GetDefenseHistory(
	ctx contractapi.TransactionContextInterface,
	incidentId string,
) ([]*DefenseAuditEvent, error) {
	record, err := loadDefenseRecord(ctx, incidentId)
	if err != nil {
		return nil, err
	}

	if err := enforceRecordReadAccess(ctx, record); err != nil {
		return nil, err
	}

	iterator, err := ctx.GetStub().GetHistoryForKey(incidentId)
	if err != nil {
		return nil, fmt.Errorf("failed to read defense history: %v", err)
	}
	defer iterator.Close()

	history := []*DefenseAuditEvent{}

	for iterator.HasNext() {
		entry, nextErr := iterator.Next()
		if nextErr != nil {
			return nil, fmt.Errorf("failed to iterate defense history: %v", nextErr)
		}

		auditItem := &DefenseAuditEvent{
			TxID:     entry.TxId,
			IsDelete: entry.IsDelete,
		}

		if entry.Timestamp != nil {
			auditItem.Timestamp = time.Unix(entry.Timestamp.Seconds, int64(entry.Timestamp.Nanos)).UTC().Format(time.RFC3339)
		}

		if !entry.IsDelete && len(entry.Value) > 0 {
			var eventRecord DefenseRecord
			if unmarshalErr := json.Unmarshal(entry.Value, &eventRecord); unmarshalErr != nil {
				return nil, fmt.Errorf("failed to unmarshal history record: %v", unmarshalErr)
			}
			auditItem.Record = &eventRecord
		}

		history = append(history, auditItem)
	}

	return history, nil
}

func loadDefenseRecord(ctx contractapi.TransactionContextInterface, incidentId string) (*DefenseRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(incidentId)
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("defense record %s does not exist", incidentId)
	}

	var record DefenseRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal defense record: %v", err)
	}

	return &record, nil
}

func saveDefenseRecord(ctx contractapi.TransactionContextInterface, record *DefenseRecord) error {
	updatedJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated record: %v", err)
	}

	return ctx.GetStub().PutState(record.IncidentID, updatedJSON)
}

func parseJSONArray(jsonInput string) ([]string, error) {
	trimmed := strings.TrimSpace(jsonInput)
	if trimmed == "" {
		return []string{}, nil
	}

	values := []string{}
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, err
	}

	return dedupeAndSort(values), nil
}

func dedupeAndSort(values []string) []string {
	seen := map[string]bool{}
	normalized := []string{}
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		normalized = append(normalized, item)
	}

	sort.Strings(normalized)
	return normalized
}

func resolveClientIdentity(ctx contractapi.TransactionContextInterface) (string, string, error) {
	orgMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve client organization: %v", err)
	}

	role, found, attrErr := ctx.GetClientIdentity().GetAttributeValue("role")
	if attrErr != nil {
		return "", "", fmt.Errorf("failed to resolve client role attribute: %v", attrErr)
	}

	if !found || strings.TrimSpace(role) == "" {
		hfType, hfFound, hfTypeErr := ctx.GetClientIdentity().GetAttributeValue("hf.Type")
		if hfTypeErr == nil && hfFound && strings.TrimSpace(hfType) != "" {
			role = hfType
		} else {
			role = "admin"
		}
	}

	return orgMSP, strings.ToLower(strings.TrimSpace(role)), nil
}

func hasRole(clientRole string, allowedRoles []string) bool {
	for _, allowed := range allowedRoles {
		if strings.EqualFold(strings.TrimSpace(clientRole), strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func hasRequiredApprovals(requiredOrgs []string, approvals []ApprovalRecord) bool {
	if len(requiredOrgs) == 0 {
		return true
	}

	approvedOrgs := map[string]bool{}
	for _, approval := range approvals {
		approvedOrgs[strings.ToLower(strings.TrimSpace(approval.OrgMSP))] = true
	}

	for _, requiredOrg := range requiredOrgs {
		if !approvedOrgs[strings.ToLower(strings.TrimSpace(requiredOrg))] {
			return false
		}
	}

	return true
}

func enforceRecordReadAccess(ctx contractapi.TransactionContextInterface, record *DefenseRecord) error {
	clientOrg, clientRole, err := resolveClientIdentity(ctx)
	if err != nil {
		return err
	}

	if hasRole(clientRole, []string{"admin"}) {
		return nil
	}

	if !containsValue(record.AllowedOrgs, clientOrg) {
		return fmt.Errorf("access denied: org %s cannot read incident %s", clientOrg, record.IncidentID)
	}

	if len(record.AllowedRoles) > 0 && !hasRole(clientRole, record.AllowedRoles) {
		return fmt.Errorf("access denied: role %s cannot read incident %s", clientRole, record.IncidentID)
	}

	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&DefenseRegistryContract{})
	if err != nil {
		log.Panicf("Error creating defenseRegistry chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting defenseRegistry chaincode: %v", err)
	}
}
