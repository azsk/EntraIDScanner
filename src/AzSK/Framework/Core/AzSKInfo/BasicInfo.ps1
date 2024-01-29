using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class BasicInfo: AzCommandBase
{    
	
	hidden [PSObject] $AzSKRG = $null
	hidden [SubConfiguration[]] $Configurations = @();
	hidden [SubConfiguration] $SubConfiguration;
	hidden [String] $AutomationAccountName = "AzSKContinuousAssurance";
	hidden [String] $AzSKRGName = ""


	BasicInfo([string] $subscriptionId, [InvocationInfo] $invocationContext): 
        Base($subscriptionId, $invocationContext) 
    { 
		$this.DoNotOpenOutputFolder = $true;
		$this.AzSKRGName = [ConfigurationManager]::GetAzSKConfigData().AzSKRGName;
		$this.AzSKRG = Get-AzResourceGroup -Name $this.AzSKRGName -ErrorAction SilentlyContinue
	}
	
	GetBasicInfo()
	{
		$rmContext = [ContextHelper]::GetCurrentRMContext();
		$this.PublishCustomMessage([Constants]::DoubleDashLine + "`r`nList of subscriptions that " + $rmContext.Account.Type.toLower() + " [" + $rmContext.Account +"] has access to`r`n" + [Constants]::SingleDashLine, [MessageType]::Default);
		
		$subscriptions = Get-AzSubscription
		$this.PublishCustomMessage(($subscriptions | Select-Object @{N='Subscription Id'; E={$_.Id}}, @{N='Subscription Name'; E={$_.Name}} | Format-Table | Out-String), [MessageType]::Default)
		$this.PublishCustomMessage([Constants]::DoubleDashLine + "`r`n",[MessageType]::Default);
		$this.PublishCustomMessage("Fetching AzSK Info for subscription...`r`n" + [Constants]::SingleDashLine, [MessageType]::Default);
        $this.PublishCustomMessage("SubscriptionId: " + "[$($this.SubscriptionContext.SubscriptionId)]" + "`r`n" ,[MessageType]::Default);
		$this.PublishCustomMessage("Name: "+  "[$($this.SubscriptionContext.SubscriptionName)]" + "`r`n" , [MessageType]::Default);

		$this.PublishCustomMessage([Constants]::SingleDashLine+ "`r`n" + "Version details of various AzSK components:" + "`r`n" + "`r`n" , [MessageType]::Default);

		$this.GetAzSKVersion()
		$this.GetAzSKAlertVersion()
		$this.GetAzSKARMPolicyVersion()
		$this.GetAzSKRBACVersion()
		$this.GetAzSKSecurityCenterVersion()
		$this.GetCAVersion()
		
		$this.PublishCustomMessage(($this.Configurations | Format-Table | Out-String), [MessageType]::Default)
	}

	GetAzSKAlertVersion()
	{
		$AlertPolicyObj =  $this.LoadServerConfigFile("Subscription.InsARMAlerts.json");
		$serverVersion = $AlertPolicyObj.Version
		$configuredVersion = "Not Available"
		$actionMessage = "Use 'Set-AzSKAlerts' to install Alerts"

		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains([Constants]::AzSKAlertsVersionTagName))
		{
			$configuredVersion = $this.AzSKRG.Tags[[Constants]::AzSKAlertsVersionTagName]
			if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
			{
				$updateAvailable = $true;
				$actionMessage = "Use 'Update-AzSKSubscriptionSecurity' to update Alerts"
			}
			else
			{
				$actionMessage = [Constants]::NoActionRequiredMessage
			}
		}

		$this.AddConfigurationDetails('Alert', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	GetAzSKARMPolicyVersion()
	{
		$ARMPolicyObj = [PSObject] $this.LoadServerConfigFile("Subscription.ARMPolicies.json"); 
		$serverVersion = $ARMPolicyObj.Version
		$configuredVersion = "Not Available"
		$actionMessage = "Use 'Set-AzSKARMPolicies' to install ARM policy"

		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains([Constants]::ARMPolicyConfigVersionTagName))
		{
			$configuredVersion = $this.AzSKRG.Tags[[Constants]::ARMPolicyConfigVersionTagName]
			if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
			{
				$updateAvailable = $true;
				$actionMessage = "Use 'Update-AzSKSubscriptionSecurity' to update ARM policy"
			}
			else
			{
				$actionMessage = [Constants]::NoActionRequiredMessage
			}
		}

		$this.AddConfigurationDetails('ARM policy', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	GetAzSKRBACVersion()
	{
		$rbacPolicy = [PSObject] $this.LoadServerConfigFile("Subscription.RBAC.json"); 
		$serverVersion = $rbacPolicy.ActiveCentralAccountsVersion
		$configuredVersion = "Not Available"
		$actionMessage = "Use 'Set-AzSKSubscriptionRBAC' to install Central accounts RBAC"

		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains([Constants]::CentralRBACVersionTagName))
		{
			$configuredVersion = $this.AzSKRG.Tags[[Constants]::CentralRBACVersionTagName]
			if($configuredVersion -ne "Not Available") 
			{
				if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
				{
					$updateAvailable = $true;
					$actionMessage = "Use 'Update-AzSKSubscriptionSecurity' to update Central accounts RBAC"
				}
				else
				{
					$actionMessage = [Constants]::NoActionRequiredMessage
				}
			}
		}
		
		$this.AddConfigurationDetails('RBAC - Central accounts', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)

		$configuredVersion = "Not Available"
		$serverVersion = $rbacPolicy.DeprecatedAccountsVersion
		$actionMessage = "Use 'Remove-AzSKSubscriptionRBAC' to remove deprecated accounts RBAC"

		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains([Constants]::DeprecatedRBACVersionTagName))
		{
			$configuredVersion = $this.AzSKRG.Tags[[Constants]::DeprecatedRBACVersionTagName]
			if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
			{
				$updateAvailable = $true;
				$actionMessage = "Use 'Update-AzSKSubscriptionSecurity' to update Deprecated accounts RBAC"
			}
			else
			{
				$actionMessage = [Constants]::NoActionRequiredMessage
			}
		}

		$this.AddConfigurationDetails('RBAC - Deprecated accounts', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	GetAzSKSecurityCenterVersion()
	{
		$secCentObj =  $this.LoadServerConfigFile("SecurityCenter.json");
		$serverVersion = $secCentObj.Version
		$configuredVersion = "Not Available"
		$actionMessage = "Use 'Set-AzSKAzureSecurityCenterPolicies' to install Security Center configuration"
		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains([Constants]::SecurityCenterConfigVersionTagName))
		{
			$configuredVersion = $this.AzSKRG.Tags[[Constants]::SecurityCenterConfigVersionTagName]
			if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
			{
				$updateAvailable = $true;
				$actionMessage = "Use 'Update-AzSKSubscriptionSecurity' to update Security Center configuration"
			}
			else
			{
				$actionMessage = [Constants]::NoActionRequiredMessage
			}
		}

		$this.AddConfigurationDetails('Security Center', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	GetAzSKVersion()
	{
		$configuredVersion = [System.Version] $this.GetCurrentModuleVersion()
		$serverVersion = [System.Version] ([ConfigurationManager]::GetAzSKConfigData().GetLatestAzSKVersion($this.GetModuleName()));
		$updateAvailable = $false;
		$actionMessage = "No Action Required"
		if($serverVersion -gt $this.GetCurrentModuleVersion()) 
		{
			$updateAvailable = $true;
			$actionMessage = "Use " + [ConfigurationManager]::GetAzSKConfigData().InstallationCommand + " to update AzSK"
        }
		else
		{
			$actionMessage = [Constants]::NoActionRequiredMessage
		}

		$this.AddConfigurationDetails('DevOpsKit (AzSK)', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	GetCAVersion()
	{
		$configuredVersion = "Not Available"
		$serverVersion = ([ConfigurationManager]::GetAzSKConfigData().AzSKCARunbookVersion);
		$actionMessage = "Use 'Install-AzSKContinuousAssurance' to install Continuous Assurance"
		if($null -ne $this.AzSKRG -and $this.AzSKRG.Tags.Count -gt 0 -and $this.AzSKRG.Tags.Contains('AzSKCARunbookVersion'))
		{
			$configuredVersion = $this.AzSKRG.Tags['AzSKCARunbookVersion']
			if([System.Version]$serverVersion -gt [System.Version]$configuredVersion)
			{
				$updateAvailable = $true;
				$actionMessage = "Use 'Update-AzSKContinuousAssurance' to update Continuous Assurance"
			}
			else
			{
				$actionMessage = [Constants]::NoActionRequiredMessage
			}
		}

		$this.AddConfigurationDetails('Continuous Assurance', $configuredVersion, $serverVersion, $serverVersion, $actionMessage)
	}

	AddConfigurationDetails([string] $ComponentName, [string] $CurrentVersion, [string] $LatestVersion, [string] $SupportedVersion, [string] $RequireAction)
	{
		$this.SubConfiguration = New-Object -TypeName PSObject
		$this.SubConfiguration.ComponentName = $ComponentName
		$this.SubConfiguration.InstalledVersion = $CurrentVersion
		$this.SubConfiguration.ServerVersion = $LatestVersion
		$this.SubConfiguration.SupportedVersion = ">= " + $SupportedVersion
		$this.SubConfiguration.Recommendation = $RequireAction
		$this.Configurations += $this.SubConfiguration
	}

}

class SubConfiguration
{
	[string] $ComponentName = "" 
	[string] $InstalledVersion = ""
	[string] $ServerVersion = ""
	[string] $SupportedVersion = ""
	[string] $Recommendation = ""
}
