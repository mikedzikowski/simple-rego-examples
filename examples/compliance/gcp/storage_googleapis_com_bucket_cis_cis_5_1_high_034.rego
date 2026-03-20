package crowdstrike

# Ensure Cloud Storage Bucket Public Access Prevention
# Framework: CIS Google Cloud Platform Foundation Benchmark v1.2.0
# Control ID: CIS-5.1
# Severity: HIGH
# Description: Storage buckets should prevent public access

default result := "fail"

# Skip non-storage.googleapis.com/Bucket resources
result = "skip" if {
    input.resource_type != "storage.googleapis.com/Bucket"
}

# Pass if policy is enforced
result = "pass" if {
    input.resource_type == "storage.googleapis.com/Bucket"
    input.configuration.iamConfiguration.publicAccessPrevention == "enforced"
}
