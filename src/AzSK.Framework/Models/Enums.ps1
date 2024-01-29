Set-StrictMode -Version Latest
enum VerificationResult
{
	Passed 
	Failed
	Verify
	Manual
	RiskAck
	Error
	Disabled
	Exception
	Remediate
	Skipped
	NotScanned
	Excluded
}

enum PolicyVerificationResult
{
	NotScanned
	Passed 
	Failed
	Verify
	Error
	NoResponse
	DefinitionNotFound
	AssignmentNotFound
	DefinitionNotInInitiative
}

enum AttestationStatus
{
	None
    NotAnIssue
	NotFixed
	WillNotFix
	WillFixLater
	ApprovedException
	NotApplicable
	StateConfirmed
}

enum AttestControls 
{
	None
	All
	AlreadyAttested
	NotAttested
}

enum MessageType
{
    Critical
    Error
    Warning
    Info
    Update
    Deprecated
	Default
}

enum ControlSeverity
{
	Critical
	High
	Medium
	Low
}


enum ScanSource
{
    SpotCheck
    VSO
    Runbook
}

enum FeatureGroup
{
	Unknown
    Subscription
    Service
}

enum ServiceScanKind
{
    Partial
    ResourceGroup
    Subscription
}

enum SubscriptionScanKind
{
    Partial
    Complete
}

enum MonitoringSolutionInstallationOption
{
	All
	Queries
	Alerts
	SampleView
	GenericView
}

enum GeneratePDF
{
	None
	Landscape
	Portrait
}

enum CAReportsLocation
{
	CentralSub
	IndividualSubs	
}

enum InfoType
{
	SubscriptionInfo
	ControlInfo
	HostInfo
	AttestationInfo
	ComplianceInfo
	SPNInfo
}

enum AutoUpdate
{
	On
	Off
	NotSet
}

enum StorageContainerType
{
	AttestationDataContainer
	CAMultiSubScanConfigContainer
	ScanProgressSnapshotsContainer
	CAScanOutputLogsContainer
}

enum TertiaryBool
{	
	False
	True
	NotSet
}

enum ComparisionType
{
	NumLesserOrEqual
}

enum OverrideConfigurationType
{
	Installer
	CARunbooks
	AzSKRootConfig
	MonitoringDashboard
	OrgAzSKVersion
	All
	None
}

enum RemoveConfiguredCASetting
{
	LAWSSettings
	AltLAWSSettings
	WebhookSettings
}

enum AssignmentType 
{
	Eligible
	Active
}

enum PolicyCacheStatus 
{
	Raw
	Final
}

enum AIOrgTelemetryStatus
{
	Undefined
	Enabled
	Disabled
}
