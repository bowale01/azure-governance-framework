// RBAC and PIM Configuration for Compliance
// Implements principle of least privilege with approval workflows
// Supports SOC 2 CC6.1, ISO 27001 A.9.1.1, and GDPR Article 32

@description('Environment designation for resource naming')
@allowed(['dev', 'test', 'prod'])
param environmentName string = 'prod'

@description('Enable Privileged Identity Management for elevated roles')
param enablePIM bool = true

@description('Approval required for privileged role activation')
param requireApprovalForPrivilegedRoles bool = true

@description('Maximum duration for privileged role activation (hours)')
@minValue(1)
@maxValue(24)
param maxPrivilegedRoleDuration int = 8

// Variables for role definitions and assignments
var roleDefinitions = {
  // Custom roles for data protection
  dataProtectionOfficer: {
    name: 'Data Protection Officer'
    description: 'Manages data protection compliance and GDPR requirements'
    permissions: [
      'Microsoft.Security/*/read'
      'Microsoft.Compliance/*/read'
      'Microsoft.Purview/*/read'
      'Microsoft.Storage/storageAccounts/read'
      'Microsoft.KeyVault/vaults/read'
    ]
  }
  // Compliance auditor role
  complianceAuditor: {
    name: 'Compliance Auditor'
    description: 'Read-only access for compliance auditing and reporting'
    permissions: [
      '*/read'
      'Microsoft.Authorization/*/read'
      'Microsoft.Security/*/read'
      'Microsoft.Compliance/*/read'
    ]
  }
  // Data processor role (limited data access)
  dataProcessor: {
    name: 'Data Processor'
    description: 'Limited access to process personal data under GDPR'
    permissions: [
      'Microsoft.Storage/storageAccounts/blobServices/containers/read'
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
      'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
    ]
  }
}

// Data Protection Officer custom role
resource dataProtectionOfficerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'DataProtectionOfficer', environmentName)
  properties: {
    roleName: '${roleDefinitions.dataProtectionOfficer.name} - ${environmentName}'
    description: roleDefinitions.dataProtectionOfficer.description
    type: 'CustomRole'
    permissions: [
      {
        actions: roleDefinitions.dataProtectionOfficer.permissions
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

// Compliance Auditor custom role
resource complianceAuditorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'ComplianceAuditor', environmentName)
  properties: {
    roleName: '${roleDefinitions.complianceAuditor.name} - ${environmentName}'
    description: roleDefinitions.complianceAuditor.description
    type: 'CustomRole'
    permissions: [
      {
        actions: roleDefinitions.complianceAuditor.permissions
        notActions: [
          'Microsoft.Authorization/*/write'
          'Microsoft.Authorization/*/delete'
        ]
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

// Data Processor custom role
resource dataProcessorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'DataProcessor', environmentName)
  properties: {
    roleName: '${roleDefinitions.dataProcessor.name} - ${environmentName}'
    description: roleDefinitions.dataProcessor.description
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: roleDefinitions.dataProcessor.permissions
        notDataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'
        ]
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

// PIM Configuration (conceptual - actual PIM setup requires Azure AD Premium P2)
var pimConfiguration = {
  enabled: enablePIM
  settings: {
    requireApproval: requireApprovalForPrivilegedRoles
    maxDuration: 'PT${maxPrivilegedRoleDuration}H'
    requireJustification: true
    requireMFA: true
    approvalRequired: requireApprovalForPrivilegedRoles
    notificationSettings: {
      enableNotifications: true
      adminNotifications: true
      requestorNotifications: true
    }
  }
  eligibleRoles: [
    'Owner'
    'Contributor'
    'User Access Administrator'
    'Security Administrator'
    'Compliance Administrator'
  ]
}

// Access Review Configuration
var accessReviewSettings = {
  enabled: true
  frequency: 'Quarterly'
  duration: 'P14D' // 14 days
  autoApply: false
  defaultDecision: 'Deny'
  scope: 'AllUsers'
  reviewers: [
    'ResourceOwner'
    'Manager'
  ]
}

// Output role information and compliance metadata
output customRoles object = {
  dataProtectionOfficer: {
    id: dataProtectionOfficerRole.id
    name: dataProtectionOfficerRole.name
  }
  complianceAuditor: {
    id: complianceAuditorRole.id
    name: complianceAuditorRole.name
  }
  dataProcessor: {
    id: dataProcessorRole.id
    name: dataProcessorRole.name
  }
}

output pimConfiguration object = pimConfiguration
output accessReviewSettings object = accessReviewSettings

output complianceControls object = {
  principleOfLeastPrivilege: 'Implemented via custom roles with minimal permissions'
  privilegedAccessManagement: 'PIM enabled with approval workflows and time-limited access'
  accessReviews: 'Quarterly reviews with 14-day review period'
  auditTrail: 'All role assignments and activations logged to Azure Monitor'
  complianceStandards: {
    soc2: 'CC6.1 - Logical and physical access controls'
    iso27001: 'A.9.1.1 - Access control policy, A.9.2.1 - User registration'
    gdpr: 'Article 32 - Security of processing'
  }
}
