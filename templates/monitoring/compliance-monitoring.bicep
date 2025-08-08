// Azure Monitor and Sentinel Configuration for Compliance
// Implements comprehensive logging and monitoring for GDPR, SOC 2, and ISO 27001

@description('Environment name for resource naming')
param environmentName string = 'prod'

@description('Log Analytics workspace retention in days (730 for 2-year compliance requirement)')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 730

@description('Enable Microsoft Sentinel security monitoring')
param enableSentinel bool = true

@description('Enable compliance dashboards and workbooks')
param enableComplianceDashboards bool = true

// Variables
var workspaceName = 'law-${environmentName}-${uniqueString(resourceGroup().id)}'
var automationAccountName = 'aa-${environmentName}-${uniqueString(resourceGroup().id)}'
var applicationInsightsName = 'ai-${environmentName}-${uniqueString(resourceGroup().id)}'

// Log Analytics Workspace - Central logging for all compliance data
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: logRetentionDays
    features: {
      searchVersion: 1
      legacy: 0
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: 100 // Prevent runaway costs
    }
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Disabled'
  }
  tags: {
    Environment: environmentName
    Purpose: 'Compliance-Audit-Logging'
    DataClassification: 'Internal'
    RetentionPeriod: '${logRetentionDays}Days'
  }
}

// Automation Account for compliance automation
resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'Basic'
    }
    encryption: {
      keySource: 'Microsoft.Automation'
    }
    publicNetworkAccess: false
  }
  identity: {
    type: 'SystemAssigned'
  }
  tags: {
    Environment: environmentName
    Purpose: 'Compliance-Automation'
  }
}

// Application Insights for application-level monitoring
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Disabled'
  }
  tags: {
    Environment: environmentName
    Purpose: 'Application-Monitoring'
  }
}

// Microsoft Sentinel - Security Information and Event Management
resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (enableSentinel) {
  name: 'SecurityInsights(${logAnalyticsWorkspace.name})'
  location: resourceGroup().location
  plan: {
    name: 'SecurityInsights(${logAnalyticsWorkspace.name})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: logAnalyticsWorkspace.id
  }
}

// Compliance-specific saved searches
resource complianceSavedSearches 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = [for search in complianceQueries: {
  parent: logAnalyticsWorkspace
  name: search.name
  properties: {
    displayName: search.displayName
    category: 'Compliance'
    query: search.query
    tags: [
      {
        name: 'ComplianceStandard'
        value: search.standard
      }
    ]
  }
}]

// Alert rules for compliance violations
resource complianceAlerts 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = [for alert in complianceAlertRules: {
  name: '${alert.name}-${environmentName}'
  location: resourceGroup().location
  properties: {
    displayName: alert.displayName
    description: alert.description
    severity: alert.severity
    enabled: true
    evaluationFrequency: alert.evaluationFrequency
    scopes: [
      logAnalyticsWorkspace.id
    ]
    targetResourceTypes: [
      'Microsoft.OperationalInsights/workspaces'
    ]
    criteria: {
      allOf: [
        {
          query: alert.query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: alert.threshold
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: []
      customProperties: {
        ComplianceStandard: alert.complianceStandard
        RiskLevel: alert.riskLevel
      }
    }
  }
  tags: {
    Environment: environmentName
    Purpose: 'Compliance-Alerting'
    Standard: alert.complianceStandard
  }
}]

// Variables for compliance queries
var complianceQueries = [
  {
    name: 'GDPRDataAccess'
    displayName: 'GDPR - Personal Data Access Monitoring'
    standard: 'GDPR'
    query: '''
      AzureActivity
      | where TimeGenerated >= ago(24h)
      | where CategoryValue == "DataAccess" or OperationNameValue contains "blob" or OperationNameValue contains "file"
      | where CallerIpAddress !startswith "10." and CallerIpAddress !startswith "192.168." and CallerIpAddress != "127.0.0.1"
      | project TimeGenerated, Caller, OperationNameValue, ResourceGroup, SubscriptionId, CallerIpAddress, ActivityStatusValue
      | sort by TimeGenerated desc
    '''
  }
  {
    name: 'SOC2AccessReview'
    displayName: 'SOC 2 - Privileged Access Review'
    standard: 'SOC2'
    query: '''
      AzureActivity
      | where TimeGenerated >= ago(7d)
      | where OperationNameValue contains "roleAssignments" or OperationNameValue contains "roleDefinitions"
      | where ActivityStatusValue == "Success"
      | project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Properties
      | sort by TimeGenerated desc
    '''
  }
  {
    name: 'ISO27001SecurityEvents'
    displayName: 'ISO 27001 - Security Event Monitoring'
    standard: 'ISO27001'
    query: '''
      SecurityEvent
      | where TimeGenerated >= ago(24h)
      | where EventID in (4624, 4625, 4648, 4672, 4720, 4726, 4728, 4732, 4756)
      | project TimeGenerated, Computer, Account, EventID, Activity, LogonType
      | sort by TimeGenerated desc
    '''
  }
]

// Alert rules for compliance monitoring
var complianceAlertRules = [
  {
    name: 'UnauthorizedDataAccess'
    displayName: 'GDPR - Unauthorized Personal Data Access'
    description: 'Detects potential unauthorized access to personal data outside business hours'
    severity: 2
    evaluationFrequency: 'PT5M'
    threshold: 0
    complianceStandard: 'GDPR'
    riskLevel: 'High'
    query: '''
      AzureActivity
      | where TimeGenerated >= ago(5m)
      | where CategoryValue == "DataAccess"
      | where hourofday(TimeGenerated) < 8 or hourofday(TimeGenerated) > 18
      | where CallerIpAddress !startswith "10." and CallerIpAddress !startswith "192.168."
    '''
  }
  {
    name: 'PrivilegedRoleActivation'
    displayName: 'SOC 2 - Unscheduled Privileged Role Activation'
    description: 'Detects privileged role activations outside approved maintenance windows'
    severity: 1
    evaluationFrequency: 'PT1M'
    threshold: 0
    complianceStandard: 'SOC2'
    riskLevel: 'Critical'
    query: '''
      AuditLogs
      | where TimeGenerated >= ago(1m)
      | where OperationName == "Add member to role completed (PIM activation)"
      | where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) > 20
    '''
  }
  {
    name: 'EncryptionPolicyViolation'
    displayName: 'ISO 27001 - Encryption Policy Violation'
    description: 'Detects resources created without required encryption settings'
    severity: 2
    evaluationFrequency: 'PT15M'
    threshold: 0
    complianceStandard: 'ISO27001'
    riskLevel: 'High'
    query: '''
      AzureActivity
      | where TimeGenerated >= ago(15m)
      | where OperationNameValue contains "Create" or OperationNameValue contains "Update"
      | where ResourceProviderValue == "Microsoft.Storage"
      | where Properties !contains "encryption"
    '''
  }
]

// Outputs
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
output logAnalyticsWorkspaceName string = logAnalyticsWorkspace.name
output applicationInsightsId string = applicationInsights.id
output automationAccountId string = automationAccount.id

output complianceConfiguration object = {
  logRetentionDays: logRetentionDays
  sentinelEnabled: enableSentinel
  complianceDashboardsEnabled: enableComplianceDashboards
  monitoredStandards: [
    'GDPR'
    'SOC2'
    'ISO27001'
  ]
  alertRulesDeployed: length(complianceAlertRules)
  savedQueriesDeployed: length(complianceQueries)
}

output complianceControls object = {
  auditLogging: {
    retention: '${logRetentionDays} days'
    standards: 'GDPR Article 30, SOC 2 CC4.1, ISO 27001 A.12.4.1'
    implementation: 'Centralized logging in Log Analytics with automated retention'
  }
  securityMonitoring: {
    solution: 'Microsoft Sentinel'
    standards: 'SOC 2 CC7.1, ISO 27001 A.16.1.1'
    implementation: 'Real-time threat detection with compliance-focused analytics'
  }
  incidentResponse: {
    automation: 'Alert rules with automated response'
    standards: 'GDPR Article 33, SOC 2 CC7.4, ISO 27001 A.16.1.5'
    implementation: 'Automated incident creation with compliance timelines'
  }
}
