package crowdstrike

# VM Access Controls
# Framework: SOC2 CC6.1 (Logical Access Controls)
# Control ID: SOC2-CC6.1
# Severity: HIGH
# Description: Virtual machines should implement access controls

default result := "fail"

# Skip non-Microsoft.Compute/virtualMachines resources
result = "skip" if {
    input.resource_type != "Microsoft.Compute/virtualMachines"
}

# Pass if not using default admin username
result = "pass" if {
    input.resource_type == "Microsoft.Compute/virtualMachines"
    input.configuration.properties.osProfile.adminUsername
    input.configuration.properties.osProfile.adminUsername != "admin"
    input.configuration.properties.osProfile.adminUsername != "administrator"
}
