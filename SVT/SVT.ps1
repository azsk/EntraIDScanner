Set-StrictMode -Version Latest
function Get-AzSKEntraIDSecurityStatusTenant
{
	<#
	.SYNOPSIS
	This command scans an Azure Active Directory (AAD) for tenant wide security issues and best practices.
	.DESCRIPTION
	This command scans various artifacts in an AAD tenant for security settings and best practices. It generates a report containing evaluation results and fix recommendations. 
	Refer AAD module section at https://aka.ms/devopskit/docs for more information.
	
	.PARAMETER TenantId
	(Optional) TenantId of the AAD tenant for which security checks need to be performed.
	
	

	.NOTES
	This command scans various artifacts in an AAD tenant for security settings and best practices.

	.LINK
	https://aka.ms/devopskit/docs 

	#>

	[OutputType([String])]
	Param
	(
		[string]		 
		[Parameter(Position = 0, Mandatory = $false, HelpMessage="AAD tenant for which security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("tid")]
		$TenantId,

		[String[]] 		 
		[Parameter(Position = 1, Mandatory = $false, HelpMessage="Comma separated list of object types to scan [Application, ServicePrincipal, Group, User, Device, All (default)].")]
		[ValidateNotNullOrEmpty()]
		[Alias("otp")]
		[ValidateSet("All","AppRegistration", "Device", "Group", "EnterpriseApplication", "User", "None")]
		$ObjectTypes = @("All"),

		[int]
		[Parameter(Position = 2, Mandatory = $false, HelpMessage="Max # of objects to check. Default is 10. When using batching set this to -1 to indicate no limit.")]
		[Alias("mo")]
		$MaxObj = 0,

		[switch]
		[Parameter(Mandatory = $false, HelpMessage = "Include detailed results in the CSV")]
		[Alias("idr")]
		$IncludeDetailedResult
	)
	Begin
	{
		[CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
		[ListenerHelper]::RegisterListeners();
	}

	Process
	{
	try 
		{
			$resolver = [AADResourceResolver]::new($TenantId, $true); #pass $true to scan tenant
			$resolver.SetScanParameters($ObjectTypes, $MaxObj);

			#If user didn't pass the tenantId, we set it after getting the login ctx (in the resolver).
			if ([string]::IsNullOrEmpty($TenantId))
			{
				$TenantId = $resolver.TenantId 
			}

			$evaluationResult = $Null;
			$totalResourcesScanned = 0;
			Do
			{
				$resolver.ClearResources();
				# Do at least one pass for non-batched scans.
				$secStatus = [ServicesSecurityStatus]::new($TenantId, $PSCmdlet.MyInvocation, $resolver);
				if ($secStatus) 
				{	
					$returnValue = $secStatus.EvaluateControlStatus();
				}
				$totalResourcesScanned += $resolver.SVTResourcesFoundCount;
			} While($resolver.SVTResourcesFoundCount -gt 0 -and $resolver.ShouldBatchScan -and $totalResourcesScanned -lt $MaxObj); 
			return $evaluationResult;
		}
		catch 
		{
			[EventBase]::PublishGenericException($_);
		}  
	}
	
	End
	{
		[ListenerHelper]::UnregisterListeners();
	}
}



function Get-AzSKEntraIDSecurityStatusUser
{
	<#
	.SYNOPSIS
	This command scans various user-created or user-owned objects in an Azure Active Directory (AAD) tenant for security issues and best practices.
	.DESCRIPTION
	This command scans various user-created or user-owned objects in an AAD tenant for security settings and best practices. 
	It generates a report containing evaluation results and fix recommendations. 
	Refer AAD module section at https://aka.ms/devopskit/docs for more information.
	
	.PARAMETER TenantId
	(Optional) TenantId of the AAD tenant for which security checks need to be performed.
	
	
	.NOTES
	This command scans various user-created or user-owned objects in an AAD tenant for security settings and best practices.

	.LINK
	https://aka.ms/devopskit/docs 

	#>
	[OutputType([String])]
	Param
	(
		[string]		 
		[Parameter(Position = 0, Mandatory = $false, HelpMessage="AAD tenant for which security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("tid")]
		$TenantId,

		[String[]]		 
		[Parameter(Position = 1, Mandatory = $false, HelpMessage="Comma separated list of object types to scan [Application, ServicePrincipal, Group, User, Device, All (default)].")]
		[ValidateNotNullOrEmpty()]
		[Alias("otp")]
		[ValidateSet("All","AppRegistration", "Device", "Group", "EnterpriseApplication", "User", "None")]
		$ObjectTypes = @("All"),		

		[int]
		[Parameter(Position = 1, Mandatory = $false, HelpMessage="Max # of objects to check. Default is 10.")]
		[Alias("mo")]
		$MaxObj,

		[switch]
		[Parameter(Mandatory = $false, HelpMessage = "Include detailed results in the CSV")]
		[Alias("idr")]
		$IncludeDetailedResult
	)
	Begin
	{
		[CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
		[ListenerHelper]::RegisterListeners();
	}

	Process
	{
	try 
		{
			$resolver = [AADResourceResolver]::new($TenantId, $false); #pass $false to indicate that the scan is for indiv. user
			$resolver.SetScanParameters($ObjectTypes, $MaxObj);
			
			#If user didn't pass the tenantId, we set it after getting the login ctx (in the resolver).
			if ([string]::IsNullOrEmpty($TenantId))
			{
				$TenantId = $resolver.TenantId 
			}
			$secStatus = [ServicesSecurityStatus]::new($TenantId, $PSCmdlet.MyInvocation, $resolver);
			if ($secStatus) 
			{		
				return $secStatus.EvaluateControlStatus();
			}    
		}
		catch 
		{
			[EventBase]::PublishGenericException($_);
		}  
	}
	
	End
	{
		[ListenerHelper]::UnregisterListeners();
	}
}