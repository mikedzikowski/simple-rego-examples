package crowdstrike

# Ensure Virtual Machine Disk Encryption
# Framework: CIS Microsoft Azure Foundations Benchmark v1.3.0
# Control ID: CIS-7.1
# Severity: HIGH
# Description: Virtual machine disks should be encrypted

default result := "fail"

# Skip non-Microsoft.Compute/virtualMachines resources
result = "skip" if {
    input.resource_type != "Microsoft.Compute/virtualMachines"
}

# Pass if security control is properly configured
result = "pass" if {
    input.resource_type == "Microsoft.Compute/virtualMachines"
    input.configuration.storageProfile.osDisk.encryptionSettings.enabled == true
}
