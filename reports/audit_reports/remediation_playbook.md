# Remediation Playbook

This playbook maps observed drift to recommended fixes and response commands.

## Event 1: Control-82
- Control Type: Endpoint
- Priority: HIGH (79.25)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 2: Control-67
- Control Type: DLP
- Priority: HIGH (71.07)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 3: Control-9
- Control Type: Endpoint
- Priority: HIGH (71.85)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 4: Control-35
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 5: Control-87
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 6: Control-60
- Control Type: Cloud_Security
- Priority: HIGH (73.91)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 7: Control-75
- Control Type: Endpoint
- Priority: MEDIUM (63.61)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 8: Control-81
- Control Type: Cloud_Security
- Priority: HIGH (75.54)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 9: Control-95
- Control Type: Cloud_Security
- Priority: HIGH (72.73)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 10: Control-30
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 11: Control-78
- Control Type: Endpoint
- Priority: MEDIUM (64.96)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 12: Control-56
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 13: Control-79
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 14: Control-71
- Control Type: Cloud_Security
- Priority: HIGH (84.99)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 15: Control-87
- Control Type: Endpoint
- Priority: MEDIUM (60.95)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 16: Control-62
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 17: Control-89
- Control Type: Cloud_Security
- Priority: HIGH (78.78)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 18: Control-1
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 19: Control-54
- Control Type: Endpoint
- Priority: HIGH (74.08)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 20: Control-97
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 21: Control-78
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 22: Control-90
- Control Type: DLP
- Priority: HIGH (65.42)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 23: Control-30
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 24: Control-42
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 25: Control-97
- Control Type: DLP
- Priority: MEDIUM (60.48)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 26: Control-3
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 27: Control-80
- Control Type: Cloud_Security
- Priority: HIGH (77.35)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 28: Control-82
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 29: Control-44
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 30: Control-82
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 31: Control-71
- Control Type: Endpoint
- Priority: HIGH (72.82)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 32: Control-18
- Control Type: Endpoint
- Priority: HIGH (67.06)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 33: Control-71
- Control Type: Cloud_Security
- Priority: HIGH (71.67)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 34: Control-94
- Control Type: DLP
- Priority: HIGH (70.51)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 35: Control-88
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 36: Control-14
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 37: Control-47
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 38: Control-27
- Control Type: DLP
- Priority: HIGH (76.03)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 39: Control-40
- Control Type: Endpoint
- Priority: HIGH (84.63)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 40: Control-79
- Control Type: Cloud_Security
- Priority: HIGH (76.39)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 41: Control-97
- Control Type: Endpoint
- Priority: HIGH (78.42)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 42: Control-76
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 43: Control-35
- Control Type: Cloud_Security
- Priority: HIGH (74.97)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 44: Control-45
- Control Type: Cloud_Security
- Priority: HIGH (65.37)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 45: Control-46
- Control Type: DLP
- Priority: HIGH (82.26)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 46: Control-98
- Control Type: Endpoint
- Priority: HIGH (81.73)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 47: Control-33
- Control Type: Endpoint
- Priority: CRITICAL (89.61)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 48: Control-88
- Control Type: DLP
- Priority: HIGH (73.18)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 49: Control-53
- Control Type: Cloud_Security
- Priority: MEDIUM (62.59)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 50: Control-41
- Control Type: Endpoint
- Priority: HIGH (68.41)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 51: Control-60
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 52: Control-40
- Control Type: Endpoint
- Priority: HIGH (79.61)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 53: Control-70
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 54: Control-70
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 55: Control-11
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 56: Control-97
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 57: Control-98
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 58: Control-5
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 59: Control-89
- Control Type: DLP
- Priority: HIGH (72.74)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 60: Control-38
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 61: Control-90
- Control Type: Endpoint
- Priority: CRITICAL (85.32)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 62: Control-81
- Control Type: Endpoint
- Priority: HIGH (68.69)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 63: Control-66
- Control Type: DLP
- Priority: HIGH (80.91)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 64: Control-63
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 65: Control-39
- Control Type: Endpoint
- Priority: HIGH (74.61)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 66: Control-66
- Control Type: Cloud_Security
- Priority: HIGH (83.88)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 67: Control-44
- Control Type: Cloud_Security
- Priority: HIGH (70.45)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 68: Control-95
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 69: Control-58
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 70: Control-61
- Control Type: Logging
- Priority: CRITICAL (95.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 71: Control-59
- Control Type: DLP
- Priority: HIGH (80.55)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 72: Control-79
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 73: Control-45
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 74: Control-64
- Control Type: Cloud_Security
- Priority: HIGH (73.17)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 75: Control-66
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 76: Control-39
- Control Type: Endpoint
- Priority: HIGH (76.72)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 77: Control-37
- Control Type: Endpoint
- Priority: HIGH (77.05)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 78: Control-85
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 79: Control-33
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 80: Control-2
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 81: Control-76
- Control Type: DLP
- Priority: HIGH (82.9)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 82: Control-50
- Control Type: Endpoint
- Priority: HIGH (78.09)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 83: Control-65
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 84: Control-11
- Control Type: DLP
- Priority: HIGH (79.22)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 85: Control-93
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 86: Control-21
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 87: Control-18
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 88: Control-88
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 89: Control-42
- Control Type: Endpoint
- Priority: HIGH (77.04)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 90: Control-37
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 91: Control-39
- Control Type: DLP
- Priority: HIGH (84.99)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 92: Control-18
- Control Type: Logging
- Priority: CRITICAL (93.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 93: Control-59
- Control Type: Endpoint
- Priority: HIGH (77.42)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 94: Control-73
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 95: Control-27
- Control Type: Endpoint
- Priority: HIGH (84.99)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 96: Control-26
- Control Type: Endpoint
- Priority: HIGH (75.57)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 97: Control-59
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 98: Control-13
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 99: Control-80
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 100: Control-58
- Control Type: Endpoint
- Priority: HIGH (66.1)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 101: Control-81
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 102: Control-87
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 103: Control-53
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 104: Control-57
- Control Type: DLP
- Priority: HIGH (76.47)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 105: Control-80
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 106: Control-22
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 107: Control-34
- Control Type: DLP
- Priority: HIGH (71.4)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 108: Control-22
- Control Type: Cloud_Security
- Priority: HIGH (73.17)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 109: Control-34
- Control Type: Endpoint
- Priority: HIGH (68.66)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 110: Control-89
- Control Type: Cloud_Security
- Priority: HIGH (74.83)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 111: Control-54
- Control Type: Cloud_Security
- Priority: HIGH (77.97)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 112: Control-6
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 113: Control-26
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 114: Control-99
- Control Type: Endpoint
- Priority: HIGH (68.84)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 115: Control-35
- Control Type: Cloud_Security
- Priority: HIGH (74.22)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 116: Control-54
- Control Type: DLP
- Priority: MEDIUM (64.59)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 117: Control-17
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 118: Control-20
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 119: Control-88
- Control Type: Endpoint
- Priority: HIGH (67.62)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 120: Control-96
- Control Type: Cloud_Security
- Priority: HIGH (81.49)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 121: Control-26
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 122: Control-40
- Control Type: Cloud_Security
- Priority: HIGH (70.76)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 123: Control-8
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 124: Control-74
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 125: Control-9
- Control Type: Cloud_Security
- Priority: HIGH (83.73)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 126: Control-34
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 127: Control-19
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 128: Control-98
- Control Type: DLP
- Priority: HIGH (70.38)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 129: Control-41
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 130: Control-12
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 131: Control-86
- Control Type: Endpoint
- Priority: HIGH (77.46)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 132: Control-16
- Control Type: Cloud_Security
- Priority: HIGH (76.72)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 133: Control-21
- Control Type: Cloud_Security
- Priority: HIGH (78.25)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 134: Control-25
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 135: Control-68
- Control Type: DLP
- Priority: MEDIUM (64.43)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 136: Control-31
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 137: Control-35
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 138: Control-89
- Control Type: Endpoint
- Priority: MEDIUM (61.99)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 139: Control-68
- Control Type: Endpoint
- Priority: HIGH (74.59)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 140: Control-2
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 141: Control-22
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 142: Control-37
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 143: Control-69
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 144: Control-77
- Control Type: DLP
- Priority: HIGH (84.62)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 145: Control-5
- Control Type: Endpoint
- Priority: MEDIUM (61.63)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 146: Control-49
- Control Type: DLP
- Priority: HIGH (67.6)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 147: Control-43
- Control Type: DLP
- Priority: HIGH (66.25)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 148: Control-22
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 149: Control-78
- Control Type: DLP
- Priority: MEDIUM (64.82)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 150: Control-26
- Control Type: DLP
- Priority: HIGH (78.72)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 151: Control-5
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 152: Control-21
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 153: Control-68
- Control Type: DLP
- Priority: HIGH (68.47)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 154: Control-94
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 155: Control-15
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 156: Control-49
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 157: Control-40
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 158: Control-36
- Control Type: Endpoint
- Priority: HIGH (66.68)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 159: Control-30
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 160: Control-10
- Control Type: Cloud_Security
- Priority: HIGH (78.67)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 161: Control-68
- Control Type: Endpoint
- Priority: HIGH (66.02)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 162: Control-39
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 163: Control-39
- Control Type: DLP
- Priority: MEDIUM (56.88)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 164: Control-80
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 165: Control-19
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 166: Control-84
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 167: Control-90
- Control Type: DLP
- Priority: MEDIUM (64.18)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 168: Control-28
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 169: Control-66
- Control Type: Endpoint
- Priority: MEDIUM (60.2)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 170: Control-61
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 171: Control-93
- Control Type: DLP
- Priority: HIGH (66.8)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 172: Control-5
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 173: Control-32
- Control Type: Endpoint
- Priority: HIGH (71.71)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 174: Control-25
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 175: Control-55
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 176: Control-86
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 177: Control-34
- Control Type: Cloud_Security
- Priority: HIGH (67.93)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 178: Control-13
- Control Type: Cloud_Security
- Priority: HIGH (66.39)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 179: Control-31
- Control Type: DLP
- Priority: HIGH (66.21)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 180: Control-88
- Control Type: Cloud_Security
- Priority: HIGH (77.36)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 181: Control-29
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 182: Control-42
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 183: Control-96
- Control Type: DLP
- Priority: HIGH (69.08)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 184: Control-51
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 185: Control-13
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 186: Control-46
- Control Type: DLP
- Priority: HIGH (66.89)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 187: Control-14
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 188: Control-85
- Control Type: Endpoint
- Priority: HIGH (76.88)
- Matched Rules: Endpoint Protection Disabled
- Compliance Impact: CIS Controls 10.1, NIST SI-3, PCI DSS 5.2

### Recommended Remediation
- Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.

### Implementation Command Templates

- `re-enable endpoint protection for the device and initiate a full malware scan`

## Event 189: Control-98
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 190: Control-86
- Control Type: DLP
- Priority: HIGH (68.47)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 191: Control-73
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 192: Control-35
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 193: Control-62
- Control Type: DLP
- Priority: HIGH (66.03)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 194: Control-46
- Control Type: Cloud_Security
- Priority: HIGH (70.48)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 195: Control-25
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 196: Control-6
- Control Type: Cloud_Security
- Priority: HIGH (71.9)
- Matched Rules: Cloud Security Policy Removed
- Compliance Impact: CIS Controls 4.1, NIST CM-3, PCI DSS 6.5.1

### Recommended Remediation
- Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.

### Implementation Command Templates

- `restore cloud guardrail policy in policy-as-code and redeploy the policy template`

## Event 197: Control-87
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 198: Control-42
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 199: Control-20
- Control Type: DLP
- Priority: MEDIUM (58.98)
- Matched Rules: DLP Rule Removed
- Compliance Impact: CIS Controls 3.13, GDPR Article 32, NIST SI-4, PCI DSS 12.3

### Recommended Remediation
- Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.

### Implementation Command Templates

- `restore DLP policy from policy-as-code and redeploy to sensitive data repositories`

## Event 200: Control-55
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 201: Control-69
- Control Type: Logging
- Priority: CRITICAL (92.0)
- Matched Rules: Audit Logging Disabled
- Compliance Impact: CIS Controls 8.2, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 202: Control-4
- Control Type: Encryption
- Priority: CRITICAL (93.0)
- Matched Rules: Encryption Downgrade
- Compliance Impact: CIS Controls 3.11, GDPR Article 32, NIST SC-13, PCI DSS 3.5

### Recommended Remediation
- Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.

### Implementation Command Templates

- `aws kms enable-key-rotation --key-id <key-id>`
- `gcloud kms keys update <key-name> --protection-level=hsm`

## Event 203: CloudTrail Disabled
- Control Type: Logging
- Priority: CRITICAL (95.0)
- Matched Rules: CloudTrail Disabled, Audit Logging Disabled
- Compliance Impact: CIS AWS 3.1, CIS Controls 8.2, NIST AU-12, NIST AU-2, NIST AU-6, PCI DSS 10.2

### Recommended Remediation
- Re-enable multi-region CloudTrail, validate log delivery, and review the actor's IAM activity.
- Restore logging, verify retention and forwarding, and investigate the change window.

### Implementation Command Templates

- `aws cloudtrail update-trail --name <trail-name> --is-logging TRUE`
- `aws cloudtrail start-logging --name <trail-name>`
- `aws logs put-retention-policy --log-group-name <group> --retention-in-days 365`
- `az monitor diagnostic-settings create --name <setting> --resource <resource-id>`

## Event 204: Firewall Rule Changed
- Control Type: Firewall
- Priority: HIGH (84.99)
- Matched Rules: Firewall Open To Internet
- Compliance Impact: CIS Controls 4.4, NIST AC-4, NIST SC-7, PCI DSS 1.3.1

### Recommended Remediation
- Restrict the source CIDR and port range, validate business need, and scan the exposed asset.

### Implementation Command Templates

- `aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --cidr 0.0.0.0/0`
- `az network nsg rule update --name <rule> --nsg-name <nsg> --priority 100`

## Event 205: MFA Disabled
- Control Type: Access_Control
- Priority: CRITICAL (95.0)
- Matched Rules: MFA Disabled, Admin Role Granted
- Compliance Impact: CIS Controls 6.3, CIS Controls 6.8, NIST AC-2, NIST AC-6, NIST IA-2, PCI DSS 7.2, PCI DSS 8.4.2

### Recommended Remediation
- Restore MFA, revoke active sessions, rotate credentials, and inspect recent sign-in activity.
- Validate approval, make access time-bound, enforce MFA, and review actions taken.

### Implementation Command Templates

- `aws iam enable-mfa-device --user-name <user> --serial-number <mfa-serial>`
- `az ad user update --id <user> --force-change-password-next-login true`
- `aws iam remove-user-from-group --user-name <user> --group-name <group>`
- `gcloud projects remove-iam-policy-binding <project> --member=user:<user> --role=<role>`
