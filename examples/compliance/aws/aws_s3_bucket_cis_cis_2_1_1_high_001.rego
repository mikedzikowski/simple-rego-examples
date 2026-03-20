package crowdstrike

# Ensure S3 Bucket Public Read Prohibited
# Framework: CIS AWS Foundations Benchmark v1.4.0
# Control ID: CIS-2.1.1
# Severity: HIGH
# Description: S3 buckets should not allow public read access

default result := "fail"

# Skip non-AWS::S3::Bucket resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.blockPublicAcls == true
}
