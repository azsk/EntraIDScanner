Set-StrictMode -Version Latest
#
# ConfigManager.ps1
#
class ConfigurationManager
{
	hidden static [AzSKConfig] GetAzSKConfigData()
 {      
		[AzSKSettings] $AzSKSettingsInstance = [ConfigurationManager]::GetAzSKSettings()
		return [AzSKConfig]::GetInstance($AzSKSettingsInstance.UseOnlinePolicyStore, $AzSKSettingsInstance.OnlinePolicyStoreUrl, $AzSKSettingsInstance.EnableAADAuthForOnlinePolicyStore)		
	}	
	
	hidden static [AzSKSettings] GetAzSKSettings()
 {        
		return [AzSKSettings]::GetInstance()
	}

	hidden static [AzSKSettings] GetLocalAzSKSettings()
 {        
		return [AzSKSettings]::GetLocalInstance()
	}

	hidden static [AzSKSettings] UpdateAzSKSettings([AzSKSettings] $localSettings)
 {        
		return [AzSKSettings]::Update($localSettings)
	}
	
	hidden static [SVTConfig] GetSVTConfig([string] $fileName)
 {     
		[AzSKSettings] $AzSKSettingsInstance = [ConfigurationManager]::GetAzSKSettings()  
		$usePolicyStore = $AzSKSettingsInstance.UseOnlinePolicyStore
		$policyStoreUrlOrFolder = $AzSKSettingsInstance.OnlinePolicyStoreUrl
		$useAADAuthForPolicyStore = $AzSKSettingsInstance.EnableAADAuthForOnlinePolicyStore 
		$defaultConfigFile = [ConfigurationHelper]::LoadServerConfigFile($fileName, $usePolicyStore, $policyStoreUrlOrFolder, $useAADAuthForPolicyStore) 
		$extendedFileName = $fileName.Replace(".json", ".ext.json");
		$extendedConfigFile = $null
		if (-not [ConfigurationHelper]::LocalPolicyEnabled)
		{
			#Default/common case... i.e., not in local policy debug mode => get .ext.json file from server.		
			$extendedConfigFile = [ConfigurationHelper]::LoadServerFileRaw($extendedFileName, $usePolicyStore, $policyStoreUrlOrFolder, $useAADAuthForPolicyStore) 
		}
		#Check if there is an .ext.json file in local org policy folder
		elseif ([ConfigurationHelper]::IsPolicyPresentOnServer($extendedFileName, $usePolicyStore, $policyStoreUrlOrFolder, $useAADAuthForPolicyStore))
		{
			Write-Warning "########## Looking for .ext.json file locally..... ##########"
			$extendedConfigFile = [ConfigurationHelper]::LoadOfflineConfigFile($extendedFileName, <#$parseJson#> $true, $policyStoreUrlOrFolder) 
		}

		$finalObject = [SVTConfig] $defaultConfigFile;
		if (-not [string]::IsNullOrWhiteSpace($extendedConfigFile))
		{
			$IdPropName = "Id"
			$finalObject = [SVTConfig]([Helpers]::MergeObjects($defaultConfigFile, $extendedConfigFile, $IdPropName));
		}        
		return $finalObject;
	}

	hidden static [PSObject] LoadServerConfigFile([string] $fileName)
 {
		[AzSKSettings] $AzSKSettingsInstance = [ConfigurationManager]::GetAzSKSettings()
		return [ConfigurationHelper]::LoadServerConfigFile($fileName, $AzSKSettingsInstance.UseOnlinePolicyStore, $AzSKSettingsInstance.OnlinePolicyStoreUrl, $AzSKSettingsInstance.EnableAADAuthForOnlinePolicyStore);
	}

	hidden static [PSObject] LoadServerFileRaw([string] $fileName)
 {
		[AzSKSettings] $AzSKSettingsInstance = [ConfigurationManager]::GetAzSKSettings()
		return [ConfigurationHelper]::LoadServerFileRaw($fileName, $AzSKSettingsInstance.UseOnlinePolicyStore, $AzSKSettingsInstance.OnlinePolicyStoreUrl, $AzSKSettingsInstance.EnableAADAuthForOnlinePolicyStore);
	}

	hidden static [string] LoadExtensionFile([string] $svtClassName)
 {
		[AzSKSettings] $AzSKSettingsInstance = [ConfigurationManager]::GetAzSKSettings()
		$extensionSVTClassName = $svtClassName + "Ext";
		$extensionFilePath = ""
		#check for extension type only if we dont find the type already loaded in to the current session
		if (-not ($extensionSVTClassName -as [type]))
		{
			#Check if we have already checked for the extentionfile and it was not present
			if ([ConfigurationHelper]::NotExtendedTypes.containsKey($svtClassName))
			{
				return $extensionFilePath
			}
			$extensionSVTClassFileName = $svtClassName + ".ext.ps1";

			if (-not [ConfigurationHelper]::LocalPolicyEnabled)
			{				
				try
				{
					$extensionFilePath = [ConfigurationManager]::DownloadExtFile($extensionSVTClassFileName)
				}
				catch
				{
					[EventBase]::PublishGenericException($_);
				}
			}
			#We are in org-policy debug mode, use local org policy folder to look for .ext.ps1 file
			#Check if an ext file exists for this class...
			elseif ([ConfigurationHelper]::IsPolicyPresentOnServer($extensionSVTClassFileName, $AzSKSettingsInstance.UseOnlinePolicyStore, $AzSKSettingsInstance.OnlinePolicyStoreUrl, $AzSKSettingsInstance.EnableAADAuthForOnlinePolicyStore))
			{
				Write-Warning "########## Looking for .ext.ps1 file locally..... ##########"
				$expectedExtFolder = Join-Path ($AzSKSettingsInstance.OnlinePolicyStoreUrl) 'Config'
				$expectedExtFile = Join-Path $expectedExtFolder $extensionSVTClassFileName

				if (Test-Path $expectedExtFile)
				{
					$extensionFilePath = $expectedExtFile
				}
				else
				{	
					[EventBase]::PublishGenericCustomMessage(("Could not find extension (.ext.ps1) file for [$svtClassName] in folder [$expectedExtFolder] in org-policy-debug mode."), [MessageType]::Error);
				}
			}
			#Store the extention not found flag so that we can skip checking for extention file again
			if ([string]::IsNullOrWhiteSpace($extensionFilePath))
			{
				[ConfigurationHelper]::NotExtendedTypes["$svtClassName"] = $true
			}
		}
		return $extensionFilePath
	}

	hidden static [string[]] RegisterExtListenerFiles()
 {
		$ServerConfigMetadata = [ConfigurationManager]::LoadServerConfigFile([Constants]::ServerConfigMetadataFileName)
		$ListenerFilePaths = @();
		if ($null -ne [ConfigurationHelper]::ServerConfigMetadata)
		{
			[ConfigurationHelper]::ServerConfigMetadata.OnlinePolicyList | ForEach-Object {
				if ([Helpers]::CheckMember($_, "Name"))
				{
					if ($_.Name -match "Listener.ext.ps1")
					{
						$listenerFileName = $_.Name
						try
						{
							$extensionFilePath = [ConfigurationManager]::DownloadExtFile($listenerFileName)
							# file has to be loaded here due to scope constraint
							$ListenerFilePaths += $extensionFilePath
						}
						catch
						{
							[EventBase]::PublishGenericException($_);
						}
					}
				}
			}
		}
		return $ListenerFilePaths;
	}

	hidden static [string] DownloadExtFile([string] $fileName)
 {
		$localExtensionsFolderPath = [Constants]::AzSKExtensionsFolderPath;
		$extensionFilePath = ""

		if (-not (Test-Path -Path $localExtensionsFolderPath))
		{
			New-Item -ItemType Directory -Path $localExtensionsFolderPath -Force
		}
		
		$extensionScriptCode = [ConfigurationManager]::LoadServerFileRaw($fileName);
		
		if (-not [string]::IsNullOrWhiteSpace($extensionScriptCode))
		{
			$extensionFilePath = Join-Path $([Constants]::AzSKExtensionsFolderPath) $fileName;
			Out-File -InputObject $extensionScriptCode -Force -FilePath $extensionFilePath -Encoding utf8;     
			Set-ItemProperty -Path $extensionFilePath -Name IsReadOnly -Value $true
		}

		return $extensionFilePath
	}
}
