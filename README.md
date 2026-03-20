# CrowdStrike Rego Policy Examples

> **⚠️ Community Repository Disclaimer**
> This is a **community-built repository** created with assistance from Claude AI and is **not officially supported by CrowdStrike**. These policy examples are provided for educational and reference purposes. For official support, documentation, and production-ready policies, please refer to [CrowdStrike's official documentation](https://falcon.crowdstrike.com/documentation) and support channels.

A comprehensive collection of **61 security policy examples** for CrowdStrike Falcon Cloud Security Posture Management (CSPM), organized by complexity and compliance frameworks.

## 📋 What's Included

- **8 Basic Examples**: Simple policies for learning Rego fundamentals
- **5 Advanced Examples**: Production-ready policies with helper functions and violation reporting
- **48 Compliance Examples**: Multi-framework policies mapped to CIS, NIST 800-53, SOC2, and PCI-DSS

## 🚀 Quick Start

1. Browse the [examples directory](./examples/) to find policies by category and cloud provider
2. All policies use modern Rego syntax compatible with Open Policy Agent (OPA)
3. Files follow consistent lowercase naming conventions
4. Schemas have been validated against real CrowdStrike resource data

## 📁 Directory Structure

```
examples/
├── basic/          # Simple learning examples
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── oci/
├── advanced/       # Production-ready examples
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── oci/
└── compliance/     # Framework-mapped policies
    ├── aws/        # 19 policies across 6 resource types
    ├── azure/      # 14 policies across 4 resource types
    ├── gcp/        # 9 policies across 3 resource types
    └── oci/        # 6 policies across 2 resource types
```

## 🛡️ Security Frameworks Covered

| Framework | Controls | Purpose |
|-----------|----------|---------|
| **CIS Benchmarks** | 15 controls | Industry baseline security compliance |
| **NIST 800-53** | 15 controls | Government/enterprise compliance |
| **SOC2** | 12 controls | Vendor assurance & audit readiness |
| **PCI-DSS** | 6 controls | Financial data protection compliance |

## 📖 Usage

These policies are designed to work with CrowdStrike's Cloud Security Posture Management API. Each policy includes:

- **Resource type validation** to ensure appropriate evaluation
- **Real security configuration checks** based on actual CrowdStrike schemas
- **Framework mapping** for compliance reporting
- **Modern Rego syntax** for compatibility

## 🔍 Policy Validation

All policies have been validated for:
- ✅ Correct CrowdStrike resource schemas
- ✅ Modern Rego syntax compatibility
- ✅ Consistent file naming (lowercase)
- ✅ Framework control mappings

---
*Generated for CrowdStrike Falcon CSPM - Comprehensive security posture visibility across multi-cloud environments*