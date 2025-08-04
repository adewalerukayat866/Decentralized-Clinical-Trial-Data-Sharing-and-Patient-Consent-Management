# Decentralized Clinical Trial Data Sharing and Patient Consent Management

A blockchain-based system for managing clinical trial data with patient consent, anonymization, integrity verification, results publication, and comprehensive audit trails.

## System Overview

This system consists of five interconnected smart contracts that work together to create a transparent, secure, and compliant clinical trial data management platform:

### 1. Patient Consent Recording Contract (\`patient-consent.clar\`)
- Securely records patient consent for clinical trial participation
- Manages consent withdrawal and updates
- Tracks consent versions and timestamps
- Ensures only authorized personnel can record consent

### 2. Anonymized Data Sharing Contract (\`data-sharing.clar\`)
- Enables researchers to access anonymized clinical trial data
- Implements access control and permission management
- Tracks data access requests and approvals
- Protects patient privacy through anonymization

### 3. Data Integrity Verification Contract (\`data-integrity.clar\`)
- Ensures accuracy and reliability of clinical trial data
- Uses cryptographic hashing for data verification
- Maintains immutable records of data modifications
- Provides tamper-proof data validation

### 4. Results Publication Contract (\`results-publication.clar\`)
- Publicly shares clinical trial results (positive and negative)
- Promotes transparency in medical research
- Manages result publication lifecycle
- Ensures regulatory compliance for result disclosure

### 5. Audit Trail Contract (\`audit-trail.clar\`)
- Maintains verifiable records of all system activities
- Tracks data access, modifications, and user actions
- Provides regulatory compliance documentation
- Enables comprehensive system monitoring

## Key Features

- **Patient Privacy**: Robust consent management and data anonymization
- **Data Integrity**: Cryptographic verification and immutable records
- **Transparency**: Public access to trial results and audit trails
- **Compliance**: Full regulatory audit capabilities
- **Security**: Role-based access control and permission management

## Contract Architecture

Each contract is designed to be independent while working cohesively:

- **Modular Design**: Each contract handles specific functionality
- **Data Isolation**: Patient data is properly anonymized and protected
- **Access Control**: Role-based permissions for different user types
- **Audit Compliance**: Complete activity logging and verification

## User Roles

- **Patients**: Provide and manage consent
- **Researchers**: Access anonymized data for studies
- **Administrators**: Manage system operations and permissions
- **Auditors**: Review compliance and audit trails
- **Publishers**: Manage result publication and disclosure

## Getting Started

1. Deploy contracts in the following order:
    - \`audit-trail.clar\`
    - \`patient-consent.clar\`
    - \`data-integrity.clar\`
    - \`data-sharing.clar\`
    - \`results-publication.clar\`

2. Initialize system administrators
3. Configure access permissions
4. Begin patient consent collection

## Testing

Run the test suite using:
\`\`\`bash
npm test
\`\`\`

Tests cover all contract functionality including:
- Consent management workflows
- Data sharing permissions
- Integrity verification processes
- Result publication lifecycle
- Audit trail generation

## Compliance

This system is designed to meet:
- HIPAA privacy requirements
- FDA clinical trial regulations
- ICH Good Clinical Practice guidelines
- Data protection and privacy laws

## Security Considerations

- All sensitive data is hashed or anonymized
- Access controls prevent unauthorized data access
- Audit trails provide complete activity tracking
- Smart contract logic prevents data tampering
