package crowdstrike

# Ensure CloudSQL Database Does Not Have Public IP Address
# Framework: NIST 800-53 SC-7 (Boundary Protection)
# Control ID: NIST-SC-7
# Severity: HIGH
# Description: CloudSQL instances should not be accessible from the public internet

default result := "fail"

# Skip non-CloudSQL resources
result = "skip" if {
    input.resource_type != "sqladmin.googleapis.com/Instance"
}

# Pass if IPv4 is explicitly disabled
result = "pass" if {
    input.resource_type == "sqladmin.googleapis.com/Instance"
    input.configuration.settings.ipConfiguration.ipv4Enabled == false
}

# Pass if private network is configured and IPv4 is not present (defaults to disabled)
result = "pass" if {
    input.resource_type == "sqladmin.googleapis.com/Instance"
    input.configuration.settings.ipConfiguration.privateNetwork
    not input.configuration.settings.ipConfiguration.ipv4Enabled
}