# BBS+ Credential Scenarios

This directory contains practical examples demonstrating the use of BBS+ signatures for privacy-preserving credentials in various contexts.

## Available Examples

### 1. Healthcare Credentials
Demonstrates how healthcare information can be selectively disclosed:
- Emergency scenarios (only blood type and allergies)
- Insurance verification (only policy and ID information)
- Referrals (sharing relevant medical information while withholding insurance details)

```
go run healthcare_credential.go
```

### 2. Digital Identity Credentials
Shows how a digital identity can be used in different contexts:
- Age verification (minimal disclosure)
- Online account registration
- Travel identification
- KYC for financial services

```
go run digital_identity.go
```

### 3. Academic Credentials
Demonstrates selective disclosure of academic achievements:
- Job application (basic degree verification)
- Graduate school application (detailed academic record)
- Academic transcript verification
- Scholarship application

```
go run academic_credentials.go
```

## Key Features Demonstrated

1. **Selective Disclosure**: Reveal only specific attributes while keeping others private
2. **Verification**: All examples demonstrate how verifiers can confirm the authenticity of credentials
3. **Holder Control**: The credential holder controls what information is shared in each context
4. **Issuer Trust**: The cryptographic properties ensure the issuer's signature remains valid even with selective disclosure

## Running the Examples

Each example can be run independently to see how BBS+ signatures enable privacy-preserving credential verification in that specific domain.

```bash
cd examples/credential_scenarios
go run healthcare_credential.go
go run digital_identity.go
go run academic_credentials.go
```

## Implementation Notes

These examples use the optimized MultiScalarMulG1 implementation which addresses previous verification issues. The credential scenarios demonstrate real-world applications where minimal disclosure is crucial for privacy.