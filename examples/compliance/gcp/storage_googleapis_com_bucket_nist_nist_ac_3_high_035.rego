package crowdstrike

# Storage Bucket Access Enforcement
# Framework: NIST 800-53 AC-3 (Access Enforcement)
# Control ID: NIST-AC-3
# Severity: HIGH
# Description: Storage buckets should enforce access controls

default result := "fail"

# Skip non-storage.googleapis.com/Bucket resources
result = "skip" if {
    input.resource_type != "storage.googleapis.com/Bucket"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "storage.googleapis.com/Bucket"
    input.configuration.iamConfiguration.uniformBucketLevelAccess.enabled == true
}
