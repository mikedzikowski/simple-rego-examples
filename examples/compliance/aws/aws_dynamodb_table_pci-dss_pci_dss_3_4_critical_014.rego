package crowdstrike

# DynamoDB Cardholder Data Encryption
# Framework: PCI-DSS Requirement 3.4
# Control ID: PCI-DSS-3.4
# Severity: CRITICAL
# Description: DynamoDB tables storing cardholder data should be encrypted

default result := "fail"

# Skip non-AWS::DynamoDB::Table resources
result = "skip" if {
    input.resource_type != "AWS::DynamoDB::Table"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.kmsMasterKeyId
}

result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.kmsMasterKeyId
    count(input.configuration.sseDescription.kmsMasterKeyId) > 0
}
