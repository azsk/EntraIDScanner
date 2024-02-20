Set-StrictMode -Version Latest 

class AppRegistration: SVTBase {    
    hidden [PSObject] $ResourceObject;
    hidden [PSObject] $MgResouceObject;
    hidden [hashtable] $DNSCache = @{};

    hidden [Hashtable] $ServicePrincipalCache;
    hidden [PsObject] $RiskyPermissions;
    hidden [PSObject] $AppOwners;

    AppRegistration([string] $tenantId, [SVTResource] $svtResource): Base($tenantId, $svtResource) {

        $objId = $svtResource.ResourceId
        $this.ResourceObject = Get-AzureADObjectByObjectId -ObjectIds $objId
        $this.MgResouceObject = Get-MgApplication -ApplicationId $objId;
        $this.ServicePrincipalCache = @{}
        $this.RiskyPermissions = [Helpers]::LoadOfflineConfigFile('Azsk.AAd.RiskyPermissions.json', $true);
        $this.AppOwners = [array] (Get-AzureADApplicationOwner -ObjectId $objId)
    }

    hidden [PSObject] GetResourceObject() {
        return $this.ResourceObject;
    }

    hidden [PsObject] GetMgResourceObject() {
        return $this.MgResouceObject;
    }

    hidden [bool] IsURLDangling([string] $uri) {
        if ($this.DNSCache.ContainsKey($uri)) {
            return $this.DNSCache[$uri];
        }
        $ownership = Resolve-DnsName -Name $uri -ErrorAction SilentlyContinue;
        if ($null -eq $ownership) {
            $this.DNSCache[$uri] = $false;
        }
        else {
            $this.DNSCache[$uri] = $true;
        }
        return $this.DNSCache[$uri];
    }

    hidden [System.Collections.ArrayList] GetExpiredSecrets([PSObject] $secrets)
    {
        $secretsWithLongExpiry = [System.Collections.ArrayList]::new();
        foreach ($secret in $secrets) { 
            if ($secret.EndDateTime -gt ([datetime]::UtcNow).AddDays($this.ControlSettings.Application.CredentialExpiryThresholdInDays)) {
                $secretsWithLongExpiry.Add([PSCustomObject]@{
                        ExpiryInDays = ($secret.EndDateTime - [datetime]::UtcNow).Days
                        SecretId     = $secret.KeyId
                    })
            }
        }
        return $secretsWithLongExpiry;
    }

    <# 
        TODO: Currently we don't fetch service prinicipals belonging to an application, so this method is not used.
        However we might need to consider the possibility of dynamically retrieving the service prinicipals for an application and 
        comparing them with the risky ones we have at a datastore like DB.
    #>
    hidden [PSObject] FetchServicePrincipalByAppId($appId) {
        if (!($this.ServicePrincipalCache.ContainsKey($appId))) {
            $this.ServicePrincipalCache[$appId] = Get-AzureADServicePrincipal -Filter "AppId eq '$($appId)'"
        }
        return $this.ServicePrincipalCache[$appId]
    }

    hidden [ControlResult] CheckOldTestDemoApps([ControlResult] $controlResult) {
        $demoAppNames = $this.ControlSettings.Application.TestDemoPoCNames 
        $demoAppsRegex = [string]::Join('|', $demoAppNames) 

        $app = $this.GetResourceObject()
        $appName = $app.DisplayName

        if ($null -eq $appName -or -not ($appName -imatch $demoAppsRegex)) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "No demo/test/pilot apps found.");
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Verify,
                "Found one or more demo/test apps. Review and cleanup.", "(TODO) Review apps that are not in use.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckReturnURLsAreHTTPS([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject()
        $verificationResult = $false

        # Initialize an empty array to store all redirect URIs
        $totalRedirectUris = @()

        # Concatenate arrays from each individual list into $totalRedirectUris
        $totalRedirectUris += $app.Spa.RedirectUris
        $totalRedirectUris += $app.Web.RedirectUris
        $totalRedirectUris += $app.PublicClient.RedirectUris

        $nonHttpURLs = @()
        if ($null -eq $totalRedirectUris -or $totalRedirectUris.Count -eq 0) {
            $verificationResult = $true
        }
        else {
            foreach ($url  in $totalRedirectUris) {
                if ($url.tolower().startswith("http:")) {
                    $nonHttpURLs += $url
                }
            }

            if ($nonHttpURLs.Count -eq 0) {
                $verificationResult = $true
            }
            else {
                $controlResult.AddMessage("Found $($nonHttpURLs.Count) non-HTTPS URLs.");
            }
        }
        
        if ($verificationResult -eq $true) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "No non-HTTPS URLs in replyURLs.");
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Failed,
                "Found one or more non-HTTPS URLs in replyURLs.", 
                "(TODO) Please review and change them to HTTPS. List of non-HTTPS URLs: $($nonHttpURLs -join ',')");
            $controlResult.DetailedResult = (ConvertTo-Json $nonHttpURLs);
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckHomePageIsHTTPS([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ((-not [String]::IsNullOrEmpty($app.HomePage)) -and $app.Homepage.ToLower().startswith('http:')) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                "Homepage url [$($app.HomePage)] for app [$($app.DisplayName)] is not HTTPS.");
        }
        <# elseif ([String]::IsNullOrEmpty($app.HomePage))   #TODO: Given API apps/functions etc. should we enforce this?
        {
            $controlResult.AddMessage([VerificationResult]::Verify,
                                    "Homepage url not set for app: [$($app.DisplayName)].");           
        } #>
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "Homepage url for app [$($app.DisplayName)] is empty/HTTPS: [$($app.HomePage)].");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckLogoutURLIsHTTPS([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ((-not [String]::IsNullOrEmpty($app.LogoutUrl)) -and $app.LogoutURL.ToLower().startswith('http:')) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                "Logout url [$($app.LogoutUrl)] for app [$($app.DisplayName)] is not HTTPS.");
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "Logout url for app [$($app.DisplayName)] is empty/HTTPS: [$($app.LogoutUrl)].");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckImplicitFlowIsNotUsed([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject()
        
        if ($app.Web.ImplicitGrantSettings.EnableAccessTokenIssuance -eq $true) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                "Implicit Authentication flow is enabled for app [$($app.DisplayName)].");
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "Implicit Authentication flow is disabled for app [$($app.DisplayName)].");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckPrivacyDisclosure([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ([String]::IsNullOrEmpty($app.InformationalUrls.Privacy) -or (-not ($app.InformationalUrls.Privacy -match [Constants]::RegExForValidURL))) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("App [$($app.DisplayName)] does not have a privacy disclosure URL set."));
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] has a privacy disclosure URL: [$($app.InformationalUrls.Privacy)]."));
        }
        return $controlResult
    }


    hidden [ControlResult] CheckAppIsCurrentTenantOnly([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject();
        
        #Currently there are 2 places this might be set, AvailableToOtherTenants setting or SignInAudience = "AzureADMultipleOrgs" (latter is new)
        if ($app.SignInAudience -ne "AzureADMyOrg") {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("The app [$($app.DisplayName)] is not limited to current enterprise tenant."));
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] is limited to current enterprise tenant."));
        }
        return $controlResult
    }

    
    hidden [ControlResult] CheckOrphanedApp([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ($null -eq $this.AppOwners -or $this.AppOwners.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] has atleast one owner configured."));
        }
        return $controlResult;
    }
    
    hidden [ControlResult] CheckAppFTEOwner([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ($null -eq $this.AppOwners -or $this.AppOwners.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        elseif ($this.AppOwners.Count -gt 0) {
            $bFTE = $false
            $this.AppOwners | % { 
                #If one of the users is non-Guest (== 'Member'), we are good.
                if ($_.UserType -ne 'Guest') { $bFTE = $true }
            }
            if ($bFTE) {
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

    hidden [ControlResult] CheckRedirectURIsWithWilcard([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject()

        # Initialize an empty array to store all redirect URIs
        $totalRedirectUris = @()

        # Concatenate arrays from each individual list into $totalRedirectUris
        $totalRedirectUris += $app.Spa.RedirectUris
        $totalRedirectUris += $app.Web.RedirectUris
        $totalRedirectUris += $app.PublicClient.RedirectUris

        if ($null -eq $totalRedirectUris -or $totalRedirectUris.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "No redirect URLs were found.");
        }
        else {
            $urlsWithWildcard = @()
            foreach ($url  in $totalRedirectUris) {
                if ($url.Contains("*")) {
                    $urlsWithWildcard += $url
                }
            }

            if ($urlsWithWildcard.Count -eq 0) {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "No redirect URLs with wildcards were found.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Failed,
                    "Following redirect URLs with wildcard characters were found: ", $($urlsWithWildcard | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $urlsWithWildcard);
            }
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckDanglingRedirectURIs([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject()

        # Initialize an empty array to store all redirect URIs
        $totalRedirectUris = @()

        # Concatenate arrays from each individual list into $totalRedirectUris
        $totalRedirectUris += $app.Spa.RedirectUris
        $totalRedirectUris += $app.Web.RedirectUris
        $totalRedirectUris += $app.PublicClient.RedirectUris

        if ($null -eq $totalRedirectUris -or $totalRedirectUris.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                "No redirect URLs were found.");
        }
        else {
            $danglingUrls = @()
            
            foreach ($url  in $totalRedirectUris) {
                $parsedUrl = $url
                if ($parsedUrl -match "http://") {
                    $parsedUrl = ($url -split "http://" -split "/")[1]
                }
                elseif ($parsedUrl -match "https://") {
                    $parsedUrl = ($url -split "https://" -split "/")[1]
                }
                else {
                    continue;
                }

                if ($parsedUrl.Contains("*")) {
                    $danglingUrls += $url
                }
                else {
                    $isUrlDangling = $this.IsURLDangling($parsedUrl);
                    if (!$isUrlDangling) {
                        $danglingUrls += $url
                    }
                }
            }
            if ($danglingUrls.Count -eq 0) {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "No dangling redirect URLs were found.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Failed,
                    "Following redirect URLs with no ownership were found: ", $($danglingUrls | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $danglingUrls);
            }
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckAppHasFTEOwnerOnly([ControlResult] $controlResult) {
        $app = $this.GetResourceObject()

        if ($null -eq $this.AppOwners -or $this.AppOwners.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        elseif ($this.AppOwners.Count -gt 0) {
            $guestOwners = @();
            $this.AppOwners | % { 
                if ($_.UserType -eq 'Guest') {
                    $guestOwners += $_.Mail
                }
            }
            if ($guestOwners.Count -gt 0) {
                $controlResult.AddMessage([VerificationResult]::Failed, "The following guest user(s) were found: ", $($guestOwners | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $guestOwners);
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "All owners of the app are FTE only.");
            }
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckOrphanedAppDoesNotHaveLongExpirySecrets([ControlResult] $controlResult)
    {
        $app = $this.GetMgResourceObject();

        $clientCredentials = $app.PasswordCredentials
        if ($null -eq $clientCredentials -or $clientCredentials.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] has no secrets configured."));
        }
        else {
            $secretsWithLongExpiry = $this.GetExpiredSecrets($clientCredentials);

            if ($secretsWithLongExpiry.Count -gt 0) {
                if ($null -eq $this.AppOwners -or $this.AppOwners.Count -eq 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed,
                    [MessageData]::new("One or more secrets of the orphaned app [$($app.DisplayName)] have long expiry (>90 days). Please review them below: "));
                    $controlResult.AddMessage(($secretsWithLongExpiry | Format-Table -AutoSize | Out-String -Width 512));
                    $controlResult.DetailedResult = ConvertTo-Json $secretsWithLongExpiry -Depth 3;
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Verify,
                    [MessageData]::new("One or more secrets of the app [$($app.DisplayName)] have long expiry (>90 days). Owners should review the secrets."));             
                }
                
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    [MessageData]::new("All secrets of app [$($app.DisplayName)] have short expiry (<=90 days)."));                
            }
        }

        return $controlResult;
    }
    
    hidden [ControlResult] CheckAppDoesNotHaveLongExpirySecrets([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject();

        $clientCredentials = $app.PasswordCredentials
        if ($null -eq $clientCredentials -or $clientCredentials.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] has no secrets configured."));
        }
        else {
            $secretsWithLongExpiry = $this.GetExpiredSecrets($clientCredentials);

            if ($secretsWithLongExpiry.Count -gt 0) {
                $controlResult.AddMessage([VerificationResult]::Failed,
                    [MessageData]::new("One or more secrets of app [$($app.DisplayName)] have long expiry (>90 days). Please review them below: "));
                $controlResult.AddMessage(($secretsWithLongExpiry | Format-Table -AutoSize | Out-String -Width 512));
                $controlResult.DetailedResult = ConvertTo-Json $secretsWithLongExpiry -Depth 3;
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    [MessageData]::new("All secrets of app [$($app.DisplayName)] have short expiry (<=90 days)."));                
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckAppUsesMiniminalPermissions([ControlResult] $controlResult) {
        $app = $this.GetResourceObject();
        $globalAppFlaggedPermissions = [System.Collections.ArrayList]::new();
        foreach ($resource in $app.RequiredResourceAccess) {
            $flaggedDelegatePermissions = [System.Collections.ArrayList]::new();
            $flaggedApplicationPermissions = [System.Collections.ArrayList]::new();
            $resourceName = "";

            foreach ($resourceAccess in $resource.ResourceAccess) {
                $resourceId = $resourceAccess.Id
                if ($null -ne $this.RiskyPermissions.PSObject.Properties[$resourceId]) {
                    $resourceName = $this.RiskyPermissions.$resourceId.ResourceName
                    $spAppPermission = $this.RiskyPermissions.$resourceId
                    if ($spAppPermission.Type -eq 'Application') {
                        $flaggedApplicationPermissions.Add($spAppPermission.PermissionName)
                    }
                    else {
                        $flaggedDelegatePermissions.Add($spAppPermission.PermissionName)
                    }
                }
            }

            if ($flaggedDelegatePermissions.Count -gt 0 -or $flaggedApplicationPermissions.Count -gt 0) {
                $globalAppFlaggedPermissions.Add([PSCustomObject]@{
                        'API/Permission Name ' = $resourceName
                        'Delegated'            = $flaggedDelegatePermissions -join ","
                        'Application'          = $flaggedApplicationPermissions -join ","
                    })
            }
        }

        if ($globalAppFlaggedPermissions.Count -gt 0) {
            $controlResult.AddMessage([VerificationResult]::Failed,
                [MessageData]::new("App [$($app.DisplayName)] uses the following risky permissions."));
            $controlResult.AddMessage(($globalAppFlaggedPermissions | Format-Table -AutoSize | Out-String -Width 512));
            $controlResult.DetailedResult = (ConvertTo-Json $globalAppFlaggedPermissions -Depth 3);
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                [MessageData]::new("App [$($app.DisplayName)] does not use risky permissions."));
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckAppInstanceLock([ControlResult] $controlResult) {
        $app = $this.GetMgResourceObject();

        # Check if the app's sign-in audience is not AzureADMyOrg which would mean only users in the given tenant can use the app
        if ((-not [String]::IsNullOrEmpty($app.SignInAudience)) -and ($app.SignInAudience -ne "AzureADMyOrg"))
        {
            try
            {
                # Invoke Graph API to retrieve app information
                $appAPIObj = [WebRequestHelper]::InvokeGraphAPI([Constants]::GraphApplicationUrl -f $this.ResourceObject.AppId)

                # Check if app instance lock property is enabled for all properties
                if($null -ne $appAPIObj.servicePrincipalLockConfiguration -and $appAPIObj.servicePrincipalLockConfiguration.isEnabled -and $appAPIObj.servicePrincipalLockConfiguration.allProperties)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                    [MessageData]::new("App instance lock property has been enabled for all properties."));    
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed,
                    [MessageData]::new("App instance lock property has not been enabled for one or more propertie(s)."));
                }
            }
            catch
            {
                # Add error message if unable to determine app instance lock property
                $controlResult.AddMessage([VerificationResult]::Error,
                [MessageData]::new("Could not determine app instance lock property of app [$($app.DisplayName)]."));
            }

        }
        else
        {
            # Add passed message if app is limited to current enterprise tenant
            $controlResult.AddMessage([VerificationResult]::Passed,
            [MessageData]::new("App [$($app.DisplayName)] is limited to current enterprise tenant."));
        }

        return $controlResult;
    }
}
