Set-StrictMode -Version Latest 
class Application: SVTBase
{    
	hidden [PSObject] $ResourceObject;
    hidden [Hashtable] $ServicePrincipalCache;
    hidden [PsObject] $RiskyPermissions;

    Application([string] $tenantId, [SVTResource] $svtResource): Base($tenantId,$svtResource) 
    {

        $objId = $svtResource.ResourceId
        $this.ResourceObject = Get-AzureADObjectByObjectId -ObjectIds $objId
        $this.ServicePrincipalCache = @{}
        $this.RiskyPermissions = [Helpers]::LoadOfflineConfigFile('Azsk.AAd.RiskyPermissions.json', $true);
    }

    hidden [PSObject] GetResourceObject()
    {
        return $this.ResourceObject;
    }

    <# 
        TODO: Currently we don't fetch service prinicipals belonging to an application, so this method is not used.
        However we might need to consider the possibility of dynamically retrieving the service prinicipals for an application and 
        comparing them with the risky ones we have at a datastore like DB.
    #>
    hidden [PSObject] FetchServicePrincipalByAppId($appId)
    {
        if (!($this.ServicePrincipalCache.ContainsKey($appId)))
        {
            $this.ServicePrincipalCache[$appId] = Get-AzureADServicePrincipal -Filter "AppId eq '$($appId)'"
        }
        return $this.ServicePrincipalCache[$appId]
    }

    hidden [ControlResult] CheckOldTestDemoApps([ControlResult] $controlResult)
	{
        $demoAppNames = $this.ControlSettings.Application.TestDemoPoCNames 
        $demoAppsRegex = [string]::Join('|', $demoAppNames) 

        $app = $this.GetResourceObject()
        $appName = $app.DisplayName

        if ($appName -eq $null -or -not ($appName -imatch $demoAppsRegex))
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "No demo/test/pilot apps found.");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Verify,
                                "Found one or more demo/test apps. Review and cleanup.","(TODO) Review apps that are not in use.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckReturnURLsAreHTTPS([ControlResult] $controlResult)
	{
        $app = $this.GetResourceObject()
        $ret = $false
        if($app.replyURLs -eq $null -or $app.replyURLs.Count -eq 0)
        {
            $ret = $true
        }
        else
        {
            $nonHttpURLs = @()
            foreach ($url  in $app.replyURLs)
            {
                if ($url.tolower().startswith("http:"))
                {
                    $nonHttpURLs += $url
                }
            }

            if ($nonHttpURLs.Count -eq 0)
            {
                $ret = $true
            }
            else
            {
                $controlResult.AddMessage("Found $($nonHttpURLs.Count) non-HTTPS URLs.");
            }
        }
        
        if ($ret -eq $true)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        "No non-HTTPS URLs in replyURLs.");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Found one or more non-HTTPS URLs in replyURLs.","(TODO) Please review and change them to HTTPS.");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckHomePageIsHTTPS([ControlResult] $controlResult)
	{
        $app = $this.GetResourceObject()

        if ((-not [String]::IsNullOrEmpty($app.HomePage)) -and $app.Homepage.ToLower().startswith('http:'))
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Homepage url [$($app.HomePage)] for app [$($app.DisplayName)] is not HTTPS.");
        }
        <# elseif ([String]::IsNullOrEmpty($app.HomePage))   #TODO: Given API apps/functions etc. should we enforce this?
        {
            $controlResult.AddMessage([VerificationResult]::Verify,
                                    "Homepage url not set for app: [$($app.DisplayName)].");           
        } #>
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        "Homepage url for app [$($app.DisplayName)] is empty/HTTPS: [$($app.HomePage)].");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckLogoutURLIsHTTPS([ControlResult] $controlResult)
	{
        $app = $this.GetResourceObject()

        if ((-not [String]::IsNullOrEmpty($app.LogoutUrl)) -and $app.LogoutURL.ToLower().startswith('http:'))
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Logout url [$($app.LogoutUrl)] for app [$($app.DisplayName)] is not HTTPS.");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        "Logout url for app [$($app.DisplayName)] is empty/HTTPS: [$($app.LogoutUrl)].");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckImplicitFlowIsNotUsed([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()
        if ($app.Oauth2AllowImplicitFlow -eq $true)
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Implicit Authentication flow is enabled for app [$($app.DisplayName)].");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        "Implicit Authentication flow is disabled for app [$($app.DisplayName)].");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckPrivacyDisclosure([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()

        if ([String]::IsNullOrEmpty($app.InformationalUrls.Privacy) -or (-not ($app.InformationalUrls.Privacy -match [Constants]::RegExForValidURL)))
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("App [$($app.DisplayName)] does not have a privacy disclosure URL set."));
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("App [$($app.DisplayName)] has a privacy disclosure URL: [$($app.InformationalUrls.Privacy)]."));
        }
        return $controlResult
    }


    hidden [ControlResult] CheckAppIsCurrentTenantOnly([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()
        
        #Currently there are 2 places this might be set, AvailableToOtherTenants setting or SignInAudience = "AzureADMultipleOrgs" (latter is new)
        if ( ($app.AvailableToOtherTenants -eq $true) -or
            (-not [String]::IsNullOrEmpty($app.SignInAudience)) -and ($app.SignInAudience -ne "AzureADMyOrg"))
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("The app [$($app.DisplayName)] is not limited to current enterprise tenant."));
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("App [$($app.DisplayName)] is limited to current enterprise tenant."));
        }
        return $controlResult
    }

    
    hidden [ControlResult] CheckOrphanedApp([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()

        $owners = [array] (Get-AzureADApplicationOwner -ObjectId $app.ObjectId)
        if ($owners -eq $null -or $owners.Count -eq 0)
        {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                        [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("App [$($app.DisplayName)] has an owner configured."));
        }
        return $controlResult;
    }
    
    hidden [ControlResult] CheckAppFTEOwner([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()

        $owners = [array] (Get-AzureADApplicationOwner -ObjectId $app.ObjectId)
        if ($owners -eq $null -or $owners.Count -eq 0)
        {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                        [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        elseif ($owners.Count -gt 0)
        {
            $bFTE = $false
            $owners | % { 
                #If one of the users is non-Guest (== 'Member'), we are good.
                if ($_.UserType -ne 'Guest') {$bFTE = $true}
            }
            if ($bFTE)
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("One or more owners of app [$($app.DisplayName)] are FTEs."));
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("All owners of app: [$($app.DisplayName)] are 'Guest' users. At least one FTE owner should be added."));                
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckAppDoesNotHaveLongExpirySecrets([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()

        $clientCredentials = $app.PasswordCredentials
        if ($null -eq $clientCredentials -or $clientCredentials.Count -eq 0)
        {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("App [$($app.DisplayName)] has no secrets configured."));
        }
        else
        {
            $expiredSecrets = [System.Collections.ArrayList]::new();
            foreach ($clientCredential in $clientCredentials) 
            { 
                if ($clientCredential.EndDate -gt ([datetime]::UtcNow).AddDays($this.ControlSettings.Application.CredentialExpiryThresholdInDays)) 
                {
                    $expiredSecrets.Add([PSCustomObject]@{
                        ExpiryInDays = ($clientCredential.EndDate - [datetime]::UtcNow).Days
                        SecretId = $clientCredential.KeyId
                    })
                }
            }

            if ($expiredSecrets.Count -gt 0)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("One or more secrets of app [$($app.DisplayName)] have long expiry (>90 days). Please review them below"));
                $controlResult.AddMessage(($expiredSecrets | Format-Table -AutoSize | Out-String -Width 512));
                $controlResult.DetailedResult = ConvertTo-Json $expiredSecrets -Depth 3;
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("All secrets of app [$($app.DisplayName)] have short expiry (<=90 days)."));                
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckAppUsesMiniminalPermissions([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject();
        $globalAppFlaggedPermissions = [System.Collections.ArrayList]::new();
        foreach ($resource in $app.RequiredResourceAccess) 
        {
            $flaggedDelegatePermissions = [System.Collections.ArrayList]::new();
            $flaggedApplicationPermissions = [System.Collections.ArrayList]::new();
            $resourceName = "";

            foreach ($resourceAccess in $resource.ResourceAccess)
            {
                $resourceId = $resourceAccess.Id
                if ($null -ne $this.RiskyPermissions.PSObject.Properties[$resourceId]) 
                {
                    $resourceName = $this.RiskyPermissions.$resourceId.ResourceName
                    $spAppPermission = $this.RiskyPermissions.$resourceId
                    if ($spAppPermission.Type -eq 'Application')
                    {
                        $flaggedApplicationPermissions.Add($spAppPermission.PermissionName)
                    }
                    else
                    {
                        $flaggedDelegatePermissions.Add($spAppPermission.PermissionName)
                    }
                }
            }

            if ($flaggedDelegatePermissions.Count -gt 0 -or $flaggedApplicationPermissions.Count -gt 0)
            {
                $globalAppFlaggedPermissions.Add([PSCustomObject]@{
                    'API/Permission Name ' = $resourceName
                    'Delegated' = $flaggedDelegatePermissions -join ","
                    'Application' = $flaggedApplicationPermissions  -join ","
                })
            }
        }

        if ($globalAppFlaggedPermissions.Count -gt 0)
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("App [$($app.DisplayName)] uses the following risky permissions."));
            $controlResult.AddMessage(($globalAppFlaggedPermissions | Format-Table -AutoSize | Out-String -Width 512));
            $controlResult.DetailedResult = (ConvertTo-Json $globalAppFlaggedPermissions -Depth 3);
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("App [$($app.DisplayName)] does not use risky permissions."));
        }

        return $controlResult;
    }
}