package crowdstrike

# Ensure No Security Groups Allow Unrestricted MSSQL Database (UDP) Access
# Framework: CIS AWS Foundations Benchmark
# Control ID: CIS-4.4
# Severity: HIGH
# Description: Security groups should not allow unrestricted access (0.0.0.0/0 or ::/0) to MSSQL Database UDP port 1434

default result := "fail"

# Skip non-AWS::EC2::SecurityGroup resources
result = "skip" if {
    input.resource_type != "AWS::EC2::SecurityGroup"
}

# Pass if no security groups allow unrestricted MSSQL UDP access
result = "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.configuration.ipPermissions
    not has_unrestricted_mssql_udp_access
}

# Helper rule to check for unrestricted MSSQL UDP access
has_unrestricted_mssql_udp_access {
    some rule in input.configuration.ipPermissions

    # Check if rule allows unrestricted access (0.0.0.0/0 or ::/0)
    has_unrestricted_cidr(rule)

    # Check if rule is for MSSQL UDP port 1434
    is_mssql_udp_port(rule)

    # Check if protocol is UDP
    is_udp_protocol(rule)
}

# Helper to check if a rule has unrestricted CIDR blocks
has_unrestricted_cidr(rule) {
    some range in rule.ipRanges
    range.cidrIp == "0.0.0.0/0"
}

has_unrestricted_cidr(rule) {
    some range in rule.ipv6Ranges
    range.cidrIpv6 == "::/0"
}

# Helper to identify MSSQL UDP port (1434)
is_mssql_udp_port(rule) {
    rule.fromPort == 1434
    rule.toPort == 1434
}

# Also catch port ranges that include 1434
is_mssql_udp_port(rule) {
    rule.fromPort <= 1434
    rule.toPort >= 1434
}

# Helper to check if protocol is UDP
is_udp_protocol(rule) {
    rule.ipProtocol == "udp"
}

# Also handle case where protocol is specified as "UDP" (uppercase)
is_udp_protocol(rule) {
    rule.ipProtocol == "UDP"
}

# Handle numeric protocol (UDP = 17)
is_udp_protocol(rule) {
    rule.ipProtocol == "17"
}