package crowdstrike

# Ensure DynamoDB Table Encryption
# Framework: CIS AWS Foundations Benchmark v1.4.0
# Control ID: CIS-2.2.1
# Severity: HIGH
# Description: DynamoDB tables should be encrypted at rest

default result := "fail"

# Skip non-AWS::DynamoDB::Table resources
result = "skip" if {
    input.resource_type != "AWS::DynamoDB::Table"
}

# Pass if service is enabled
result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.status == "ENABLED"
}

result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.status == "enabled"
}
