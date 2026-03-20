package crowdstrike

# Simple S3 Public Access Check
# Description: Basic example to check if S3 bucket allows public access

default result := "fail"

# Skip non-S3 resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if public access is blocked
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true
}