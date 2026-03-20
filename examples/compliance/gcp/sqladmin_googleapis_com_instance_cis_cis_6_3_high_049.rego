package crowdstrike

# Ensure CloudSQL Database Has No Authorized Networks
# Framework: CIS Google Cloud Platform Foundation Benchmark v1.2.0
# Control ID: CIS-6.3
# Severity: HIGH
# Description: CloudSQL instances should not have authorized networks configured to minimize attack surface

default result := "pass"

# Skip non-CloudSQL resources
result = "skip" if {
    input.resource_type != "sqladmin.googleapis.com/Instance"
}

# Fail if authorized networks are configured (security risk)
result = "fail" if {
    input.resource_type == "sqladmin.googleapis.com/Instance"
    count(input.configuration.settings.ipConfiguration.authorizedNetworks) > 0
}