#Requires -Modules Az.Accounts, Az.Security, Az.Resources, Az.Monitor
<#
.SYNOPSIS
    GDPR Data Discovery and Classification Automation
    
.DESCRIPTION
    Automates the discovery and classification of personal data for GDPR compliance.
    Implements data inventory requirements per GDPR Article 30 (Records of processing activities).
    
.PARAMETER SubscriptionId
    Azure subscription ID to scan for personal data
    
.PARAMETER ResourceGroupName
    Specific resource group to scan (optional - scans all if not specified)
    
.PARAMETER GenerateReport
    Generate detailed compliance report
    
.EXAMPLE
    .\Invoke-GDPRDataDiscovery.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -GenerateReport
    
.NOTES
    Compliance Framework: GDPR Article 30, SOC 2 CC6.1, ISO 27001 A.18.1.4
    Author: Azure Governance Framework
    Requires: Azure PowerShell modules and appropriate RBAC permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\GDPR-DataInventory-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
)

# Initialize compliance tracking
$ComplianceResults = @{
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    SubscriptionId = $SubscriptionId
    ScanScope = if ($ResourceGroupName) { $ResourceGroupName } else { "All Resource Groups" }
    PersonalDataDiscovered = @()
    SecurityFindings = @()
    ComplianceStatus = @{}
    Recommendations = @()
}

# Personal data patterns for detection
$PersonalDataPatterns = @{
    Email = @{
        Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        Classification = 'PersonalData'
        GDPRCategory = 'Contact Information'
    }
    PhoneNumber = @{
        Pattern = '\+?[1-9]\d{1,14}'
        Classification = 'PersonalData'
        GDPRCategory = 'Contact Information'
    }
    SSN = @{
        Pattern = '\b\d{3}-\d{2}-\d{4}\b'
        Classification = 'SensitivePersonalData'
        GDPRCategory = 'National Identification'
    }
    CreditCard = @{
        Pattern = '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        Classification = 'SensitivePersonalData'
        GDPRCategory = 'Financial Information'
    }
}

function Write-ComplianceLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $LogMessage -ForegroundColor Red }
        "Warning" { Write-Host $LogMessage -ForegroundColor Yellow }
        "Success" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage -ForegroundColor White }
    }
}

function Test-PersonalDataInStorage {
    param(
        [object]$StorageAccount
    )
    
    Write-ComplianceLog "Scanning storage account: $($StorageAccount.StorageAccountName)"
    
    $PersonalDataFound = @()
    
    try {
        # Get storage account context
        $Context = (Get-AzStorageAccount -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName).Context
        
        # Scan blob containers
        $Containers = Get-AzStorageContainer -Context $Context
        
        foreach ($Container in $Containers) {
            $Blobs = Get-AzStorageBlob -Container $Container.Name -Context $Context
            
            foreach ($Blob in $Blobs) {
                # Check blob metadata for personal data indicators
                $Metadata = $Blob.ICloudBlob.Metadata
                
                foreach ($Key in $Metadata.Keys) {
                    $Value = $Metadata[$Key]
                    
                    foreach ($PatternName in $PersonalDataPatterns.Keys) {
                        $Pattern = $PersonalDataPatterns[$PatternName]
                        
                        if ($Value -match $Pattern.Pattern) {
                            $PersonalDataFound += @{
                                Location = "$($StorageAccount.StorageAccountName)/$($Container.Name)/$($Blob.Name)"
                                DataType = $PatternName
                                Classification = $Pattern.Classification
                                GDPRCategory = $Pattern.GDPRCategory
                                DetectionMethod = "Metadata Analysis"
                                RiskLevel = if ($Pattern.Classification -eq "SensitivePersonalData") { "High" } else { "Medium" }
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ComplianceLog "Error scanning storage account $($StorageAccount.StorageAccountName): $($_.Exception.Message)" -Level "Error"
    }
    
    return $PersonalDataFound
}

function Get-SecurityFindings {
    param(
        [string]$SubscriptionId
    )
    
    Write-ComplianceLog "Retrieving security findings from Azure Security Center"
    
    $SecurityFindings = @()
    
    try {
        # Get Security Center alerts
        $SecurityAlerts = Get-AzSecurityAlert -SubscriptionId $SubscriptionId
        
        foreach ($Alert in $SecurityAlerts) {
            if ($Alert.AlertDisplayName -match "data|personal|privacy|gdpr" -or 
                $Alert.Description -match "data|personal|privacy|gdpr") {
                
                $SecurityFindings += @{
                    AlertName = $Alert.AlertDisplayName
                    Description = $Alert.Description
                    Severity = $Alert.ReportedSeverity
                    Status = $Alert.State
                    ResourceId = $Alert.ResourceIdentifiers
                    ComplianceImpact = "Potential GDPR compliance risk"
                }
            }
        }
        
        # Get Security Center compliance assessments
        $Assessments = Get-AzSecurityAssessment -SubscriptionId $SubscriptionId
        
        foreach ($Assessment in $Assessments) {
            if ($Assessment.DisplayName -match "encryption|access|data|privacy") {
                $SecurityFindings += @{
                    AssessmentName = $Assessment.DisplayName
                    Status = $Assessment.Status.Code
                    Description = $Assessment.Status.Description
                    ComplianceStandard = "Security baseline"
                    ComplianceImpact = "GDPR Article 32 - Security of processing"
                }
            }
        }
    }
    catch {
        Write-ComplianceLog "Error retrieving security findings: $($_.Exception.Message)" -Level "Error"
    }
    
    return $SecurityFindings
}

function New-ComplianceRecommendations {
    param(
        [array]$PersonalDataFound,
        [array]$SecurityFindings
    )
    
    $Recommendations = @()
    
    # Data classification recommendations
    if ($PersonalDataFound.Count -gt 0) {
        $Recommendations += @{
            Priority = "High"
            Category = "Data Classification"
            Recommendation = "Implement Azure Information Protection labels for discovered personal data"
            ComplianceControl = "GDPR Article 32 - Implement appropriate technical measures"
            ActionRequired = "Apply sensitivity labels and encryption to personal data stores"
        }
        
        $SensitiveData = $PersonalDataFound | Where-Object { $_.Classification -eq "SensitivePersonalData" }
        if ($SensitiveData.Count -gt 0) {
            $Recommendations += @{
                Priority = "Critical"
                Category = "Data Protection"
                Recommendation = "Enhanced protection required for sensitive personal data"
                ComplianceControl = "GDPR Article 9 - Special categories of personal data"
                ActionRequired = "Implement additional encryption and access controls"
            }
        }
    }
    
    # Security recommendations
    if ($SecurityFindings.Count -gt 0) {
        $HighSeverityFindings = $SecurityFindings | Where-Object { $_.Severity -eq "High" }
        if ($HighSeverityFindings.Count -gt 0) {
            $Recommendations += @{
                Priority = "Critical"
                Category = "Security"
                Recommendation = "Address high-severity security findings immediately"
                ComplianceControl = "SOC 2 CC6.1, ISO 27001 A.12.6.1"
                ActionRequired = "Remediate security vulnerabilities affecting personal data"
            }
        }
    }
    
    return $Recommendations
}

# Main execution
try {
    Write-ComplianceLog "Starting GDPR Data Discovery and Classification" -Level "Success"
    Write-ComplianceLog "Subscription: $SubscriptionId"
    
    # Connect to Azure
    $Context = Get-AzContext
    if (-not $Context -or $Context.Subscription.Id -ne $SubscriptionId) {
        Write-ComplianceLog "Connecting to Azure subscription: $SubscriptionId"
        Set-AzContext -SubscriptionId $SubscriptionId
    }
    
    # Get storage accounts
    $StorageAccounts = if ($ResourceGroupName) {
        Get-AzStorageAccount -ResourceGroupName $ResourceGroupName
    } else {
        Get-AzStorageAccount
    }
    
    Write-ComplianceLog "Found $($StorageAccounts.Count) storage accounts to scan"
    
    # Scan for personal data
    $AllPersonalData = @()
    foreach ($StorageAccount in $StorageAccounts) {
        $PersonalData = Test-PersonalDataInStorage -StorageAccount $StorageAccount
        $AllPersonalData += $PersonalData
    }
    
    # Get security findings
    $SecurityFindings = Get-SecurityFindings -SubscriptionId $SubscriptionId
    
    # Generate recommendations
    $Recommendations = New-ComplianceRecommendations -PersonalDataFound $AllPersonalData -SecurityFindings $SecurityFindings
    
    # Update compliance results
    $ComplianceResults.PersonalDataDiscovered = $AllPersonalData
    $ComplianceResults.SecurityFindings = $SecurityFindings
    $ComplianceResults.Recommendations = $Recommendations
    $ComplianceResults.ComplianceStatus = @{
        PersonalDataInventory = if ($AllPersonalData.Count -gt 0) { "Personal data discovered - classification required" } else { "No personal data patterns detected" }
        DataProtectionMeasures = "Review security findings and implement recommendations"
        GDPRCompliance = if ($AllPersonalData.Count -gt 0) { "Action required" } else { "Monitoring ongoing" }
        OverallRisk = if ($AllPersonalData | Where-Object { $_.Classification -eq "SensitivePersonalData" }) { "High" } else { "Medium" }
    }
    
    # Output results
    Write-ComplianceLog "Personal data instances found: $($AllPersonalData.Count)" -Level "Success"
    Write-ComplianceLog "Security findings: $($SecurityFindings.Count)" -Level "Success"
    Write-ComplianceLog "Recommendations generated: $($Recommendations.Count)" -Level "Success"
    
    if ($GenerateReport) {
        $ComplianceResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-ComplianceLog "Compliance report saved to: $OutputPath" -Level "Success"
    }
    
    # Display summary
    Write-Host "`n=== GDPR Compliance Summary ===" -ForegroundColor Cyan
    Write-Host "Personal Data Discovered: $($AllPersonalData.Count) instances" -ForegroundColor Yellow
    Write-Host "Security Findings: $($SecurityFindings.Count) items" -ForegroundColor Yellow
    Write-Host "Recommendations: $($Recommendations.Count) actions" -ForegroundColor Yellow
    Write-Host "Overall Risk Level: $($ComplianceResults.ComplianceStatus.OverallRisk)" -ForegroundColor $(if ($ComplianceResults.ComplianceStatus.OverallRisk -eq "High") { "Red" } else { "Yellow" })
    
    return $ComplianceResults
}
catch {
    Write-ComplianceLog "GDPR Data Discovery failed: $($_.Exception.Message)" -Level "Error"
    throw
}
