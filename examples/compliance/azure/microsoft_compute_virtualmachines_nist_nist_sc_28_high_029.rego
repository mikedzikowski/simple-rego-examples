package crowdstrike

# VM Information Protection at Rest
# Framework: NIST 800-53 SC-28 (Protection of Information at Rest)
# Control ID: NIST-SC-28
# Severity: HIGH
# Description: Virtual machines should protect information at rest

default result := "fail"

# Skip non-Microsoft.Compute/virtualMachines resources
result = "skip" if {
    input.resource_type != "Microsoft.Compute/virtualMachines"
}

# Pass if information is protected at rest (using CrowdStrike insights)
result = "pass" if {
    input.resource_type == "Microsoft.Compute/virtualMachines"
    input.cloud_context.insights.details.encryptedAtRest.value == true
}
