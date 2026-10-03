package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// DefenseRecord represents a validated defense stored on the ledger.
type DefenseRecord struct {
	IncidentID       string `json:"incidentId"`
	AttackType       string `json:"attackType"`
	MitreTechnique   string `json:"mitreTechnique"`
	SourceIP         string `json:"sourceIp"`
	TargetSystem     string `json:"targetSystem"`
	RiskScore        string `json:"riskScore"`
	AgentConfidence  string `json:"agentConfidence"`
	EvidenceHash     string `json:"evidenceHash"`
	DefenseRule      string `json:"defenseRule"`
	ValidationStatus string `json:"validationStatus"`
	LifecycleStatus  string `json:"lifecycleStatus"`
	Timestamp        string `json:"timestamp"`
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
) error {
	existing, err := ctx.GetStub().GetState(incidentId)
	if err != nil {
		return fmt.Errorf("failed to read ledger: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("defense record %s already exists", incidentId)
	}

	record := DefenseRecord{
		IncidentID:       incidentId,
		AttackType:       attackType,
		MitreTechnique:   mitreTechnique,
		SourceIP:         sourceIP,
		TargetSystem:     targetSystem,
		RiskScore:        riskScore,
		AgentConfidence:  agentConfidence,
		EvidenceHash:     evidenceHash,
		DefenseRule:      defenseRule,
		ValidationStatus: validationStatus,
		LifecycleStatus:  "VALIDATED",
		Timestamp:        timestamp,
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

	record.LifecycleStatus = newStatus

	updatedJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated record: %v", err)
	}

	return ctx.GetStub().PutState(incidentId, updatedJSON)
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

		records = append(records, &record)
	}

	return records, nil
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
