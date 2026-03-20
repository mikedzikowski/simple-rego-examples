package crowdstrike

# DynamoDB Protection of Information at Rest
# Framework: NIST 800-53 SC-28 (Protection of Information at Rest)
# Control ID: NIST-SC-28
# Severity: HIGH
# Description: DynamoDB tables should protect information at rest

default result := "fail"

# Skip non-AWS::DynamoDB::Table resources
result = "skip" if {
    input.resource_type != "AWS::DynamoDB::Table"
}

# Pass if security configuration exists
result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.sseType
}

result = "pass" if {
    input.resource_type == "AWS::DynamoDB::Table"
    input.configuration.sseDescription.sseType
    count(input.configuration.sseDescription.sseType) > 0
}
