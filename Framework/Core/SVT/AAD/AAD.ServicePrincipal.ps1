Set-StrictMode -Version Latest 
class EnterpriseApplication: SVTBase
{    
    hidden [PSObject] $ResourceObject;
    hidden [PSObject] $MgResourceObject;
    hidden [String] $SPNName;
    hidden [psobject] $RiskyPermissions;
    hidden [hashtable] $RiskyAdminConsentPermissionsCache;
    hidden [hashtable] $RiskyUserConsentPermissionsCache;

    EnterpriseApplication([string] $tenantId, [SVTResource] $svtResource): Base($tenantId, $svtResource) 
    {
        #$this.GetMgResourceObject();
        $objId = $svtResource.ResourceId
        $this.MgResourceObject = Get-MgServicePrincipal -ServicePrincipalId $objId;

        $this.SPNName = $this.ResourceObject.DisplayName
        $this.RiskyPermissions = [Helpers]::LoadOfflineConfigFile('Azsk.AAD.RiskyPermissions.json', $true);
    }

    hidden [PSObject] GetMgResourceObject()
    {
        return $this.MgResourceObject;
    }

    hidden [ControlResult] CheckSPNPasswordCredentials([ControlResult] $controlResult)
	{
        $spn = $this.GetMgResourceObject()

        if ($spn.PasswordCredentials.Count -gt 0)
        {
                $nPswd = $spn.PasswordCredentials.Count


                $controlResult.AddMessage([VerificationResult]::Failed,
                                        [MessageData]::new("Found $nPswd password credentials on SPN: $($this.SPNName).")); 
                                        
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("Did not find any password credentials on SPN."));
        }
        return $controlResult;
    }
 
    hidden [ControlResult] ReviewLegacySPN([ControlResult] $controlResult)
	{
        $spn = $this.GetMgResourceObject()

        if ($spn.ServicePrincipalType -eq 'Legacy')
        {
                $controlResult.AddMessage([VerificationResult]::Verify,
                                        [MessageData]::new("Found an SPN of type 'Legacy'. Please review: $($this.SPNName)"));
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        [MessageData]::new("SPN is not of type 'Legacy'."));
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckCertNearingExpiry([ControlResult] $controlResult)
    {
        $spn = $this.GetMgResourceObject()

        $spk = [array] $spn.KeyCredentials

        if ($spk -eq $null -or $spk.Count -eq 0)
        {
            #No key creds, pass the control.
            $controlResult.AddMessage([VerificationResult]::Passed,
                                [MessageData]::new("SPN [$($spn.DisplayName)] does not have a key credential configured. Passing control by default."));

        }
        else 
        {
            $renew = @()
            $expireDays = $this.ControlSettings.ServicePrincipal.ApproachingExpiryThresholdInDays;
            $expiringSoon = ([DateTime]::Today).AddDays($expireDays)  
            $needToRenew = $false
            $spk | % {
                $k = $_
                if ($k.EndDate -le $expiringSoon)
                {
                    $renew += $k.KeyId
                    $needToRenew = $true
                }
            }

            if ($needToRenew -eq $true) #found some key close to expiry
            {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("One or more keys of SPN [$($spn.DisplayName)] have expired or are nearing expiry (<$expireDays days)."));

                $renewList = $renew -join ", "
                $controlResult.AddMessage([MessageData]::new("KeyIds nearing expiry:`n`t$renewList"));
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                            [MessageData]::new("None of the configured keys for SPN [$($spn.DisplayName)] are nearing expiry (<$expireDays days)."));
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckEnterpriseApplicationHasFTEOwnerOnly([ControlResult] $controlResult)
    {
        $app = $this.GetMgResourceObject()

        $owners = [array] (Get-MgServicePrincipalOwner -ServicePrincipalId $app.ObjectId)
        if ($owners -eq $null -or $owners.Count -eq 0)
        {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                        [MessageData]::new("App [$($app.DisplayName)] has no owner configured."));
        }
        elseif ($owners.Count -gt 0)
        {
            $guestOwners = @();
            $owners | % { 
                if ($_.UserType -eq 'Guest') 
                {
                    $guestOwners += $_.Mail
                }
            }
            if ($guestOwners.Count -gt 0)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"The following guest user(s) were found: ", $($guestOwners | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $guestOwners);
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("All owners of the enterprise application [$($app.DisplayName)] are FTEs."));                
            }
        }
        return $controlResult;
    }

    hidden [hashtable] GetAdminConsentPermissions()
    {
        $spn = $this.GetMgResourceObject();
        $adminConsentRiskyPermissions = @{};

        # Application Level Permissions
        $applicationPermissionGrouping = (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $spn.Id) | Group-Object -Property ResourceId;
        foreach($applicationPermissionGroup in $applicationPermissionGrouping)
        {
            foreach($permission in $applicationPermissionGroup.Group)
            {
                if ($null -ne $this.RiskyPermissions.PsObject.Properties[$permission.Id])
                {
                    $permissionId = $permission.Id;
                    if($adminConsentRiskyPermissions.ContainsKey($permission.ResourceId))
                    {
                        $adminConsentRiskyPermissions[$permission.ResourceId].Application.Add($this.RiskyPermissions.$permissionId.PermissionName);
                    }
                    else
                    {
                        $adminConsentRiskyPermissions[$permission.ResourceId] = [PSCustomObject]@{
                            Name = $permission.ResourceDisplayName
                            Delegated = [System.Collections.Generic.List[string]]::new()
                            Application = [System.Collections.Generic.List[string]]::new()
                        };
                        $adminConsentRiskyPermissions[$permission.ResourceId].Application.Add($this.RiskyPermissions.$permissionId.PermissionName);
                    }   
                }
            }
        }

        $delegatedPermissionGrants = @(Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $spn.Id | Where-Object { $_.ConsentType -eq 'AllPrincipals' })
        if ($delegatedPermissionGrants.Count -eq 0)
        {
            return $adminConsentRiskyPermissions;
        }

        $spns = ([ResourceHelper]::FetchResourcesByObjectIdsAndCache(($delegatedPermissionGrants| ForEach-Object { $_.ResourceId })) | Group-Object -Property Id -AsHashTable);
        foreach($delegatedPermissionGrant in $delegatedPermissionGrants)
        {
            $resourceId = $delegatedPermissionGrant.ResourceId;
            $scopes = [System.Collections.Generic.HashSet[string]]::new($delegatedPermissionGrant.Scope.Split(" "));
            $riskyAdminConsentDelegatedPermissions = $spns[$resourceId].AdditionalProperties.oauth2PermissionScopes | 
                Where-Object { $scopes.Contains($_.value) -and $null -ne $this.RiskyPermissions.PsObject.Properties[$_.id]}
            if ($null -eq $riskyAdminConsentDelegatedPermissions -or $riskyAdminConsentDelegatedPermissions.Count -eq 0)
            {
                continue;
            }

            if (!$adminConsentRiskyPermissions.ContainsKey($resourceId))
            {
                $adminConsentRiskyPermissions[$resourceId] = [PSCustomObject]@{
                    Name = $spns[$resourceId].AdditionalProperties.DisplayName
                    Delegated = $riskyAdminConsentDelegatedPermissions.value
                    Application = [System.Collections.Generic.List[string]]::new()
                };
            }
            else 
            {
                $adminConsentRiskyPermissions[$resourceId].Delegated = $riskyAdminConsentDelegatedPermissions.value;
            }
        }

        return $adminConsentRiskyPermissions;
    }

    hidden [hashtable] GetUserConsentRiskyPermissions()
    {
        $spn = $this.GetMgResourceObject();
        $userConsentRiskyPermissions = @{}
    
        $delegatedPermissionGrants = @(Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $spn.Id | Where-Object { $_.ConsentType -eq 'Principal' });
        if ($delegatedPermissionGrants.Count -eq 0)
        {
            return $userConsentRiskyPermissions;
        }
 
        $spns = ([ResourceHelper]::FetchResourcesByObjectIdsAndCache(($delegatedPermissionGrants| ForEach-Object { $_.ResourceId })) | Group-Object -Property Id -AsHashTable);
        foreach($delegatedPermissionGrant in $delegatedPermissionGrants)
        {      
            $resourceId = $delegatedPermissionGrant.ResourceId;
            $scopes = [System.Collections.Generic.HashSet[string]]::new($delegatedPermissionGrant.Scope.Split(" "));
            $riskyUserConsentDelegatedPermissions = $spns[$resourceId].AdditionalProperties.oauth2PermissionScopes | 
                Where-Object { $scopes.Contains($_.value) -and $null -ne $this.RiskyPermissions.PsObject.Properties[$_.id]}
                
            if ($null -eq $riskyUserConsentDelegatedPermissions -or $riskyUserConsentDelegatedPermissions.Count -eq 0)
            {
                continue;
            }

            if (!$userConsentRiskyPermissions.ContainsKey($resourceId))
            {
                $userConsentRiskyPermissions[$resourceId] = [PSCustomObject]@{
                    Name = $spns[$resourceId].DisplayName
                    Users = [System.Collections.Generic.HashSet[guid]]::new()
                    Delegated = [System.Collections.Generic.HashSet[string]]::new()
                };
                [void]$userConsentRiskyPermissions[$resourceId].Delegated.Add($riskyUserConsentDelegatedPermissions.value);
                [void]$userConsentRiskyPermissions[$resourceId].Users.Add($delegatedPermissionGrant.PrincipalId)
            }
            else 
            {
                [void]$userConsentRiskyPermissions[$resourceId].Delegated.Add($riskyUserConsentDelegatedPermissions.value);
                [void]$userConsentRiskyPermissions[$resourceId].Users.Add($delegatedPermissionGrant.PrincipalId);
            }
        }

        return $userConsentRiskyPermissions;
    }

    hidden [void] FetchAndCacheRiskyPermissions($includeUserConsentPermissions = $false)
    {
        if($null -eq $this.RiskyAdminConsentPermissionsCache)
        {
            $this.RiskyAdminConsentPermissionsCache = $this.GetAdminConsentPermissions();
        }
        
        if($includeUserConsentPermissions -and $null -eq $this.RiskyUserConsentPermissionsCache)
        {
            $this.RiskyUserConsentPermissionsCache = $this.GetUserConsentRiskyPermissions();
        }
    }

    hidden [void] VerifyAndReportRiskyPermissions([ControlResult] $controlResult)
    {
        $includeUserConsentPermissions = $this.ControlSettings.ServicePrincipal.IncludeUserConsentPermissions -or $true;
        $this.FetchAndCacheRiskyPermissions($includeUserConsentPermissions);
        if ($this.RiskyAdminConsentPermissionsCache.Count -eq 0 -and (!$includeUserConsentPermissions -or $this.RiskyUserConsentPermissionsCache.Count -eq 0))
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("The enterprise application does not have any risky permissions."));
            return;
        }
            
        if ($this.RiskyAdminConsentPermissionsCache.Count -gt 0)
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("The following risky permissions are granted to the enterprise application with admin consent: $($this.SPNName)"));
            $controlResult.AddMessage(($this.RiskyAdminConsentPermissionsCache.Values | ForEach-Object {[PSCustomObject]@{
                'API/Permission Name' = $_.Name
                'Delegated Permissions' = $_.Delegated -join ','
                'Application Permissions' = $_.Application -join ','
            }} | Format-Table -AutoSize | Out-String -Width 512));
            $controlResult.DetailedResult = (ConvertTo-Json $this.RiskyAdminConsentPermissionsCache -Depth 5);
        }
    
        if ($includeUserConsentPermissions -and $this.RiskyUserConsentPermissionsCache.Count -gt 0)
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
            [MessageData]::new("The following risky permissions are granted to the enterprise application with user consent: $($this.SPNName)"));
    
            $controlResult.AddMessage(($this.RiskyUserConsentPermissionsCache.Values | ForEach-Object {[PSCustomObject]@{
                'API/Permission Name' = $_.Name
                'Users Count' = $_.Users.Count
                'Delegated Permissions' = $_.Delegated -join ','
            }} | Format-Table -AutoSize | Out-String -Width 512));
            $controlResult.DetailedResult = (ConvertTo-Json $this.RiskyUserConsentPermissionsCache -Depth 5);
        }
    }

    hidden [ControlResult] CheckEnterpriseAppUsesMiniminalPermissions([ControlResult] $controlResult)
    {
        $spn = $this.GetMgResourceObject();
        if($spn.ServicePrincipalType -ne "Application")
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("The enterprise application is not of type 'Application'."));
            return $controlResult              
        }

        # TODO: Parametrize the $includeUserConsentPermissions
        $this.VerifyAndReportRiskyPermissions($controlResult);

        return $controlResult;
    }

    hidden [ControlResult] CheckEnterpriseMultiTenantAppUsesMiniminalPermissions([ControlResult] $controlResult)
    {
        $spn = $this.GetMgResourceObject();
        if($spn.ServicePrincipalType -ne "Application")
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("The enterprise application is not of type 'Application'."));
            return $controlResult              
        }
    
        if($spn.AppOwnerOrganizationId -eq $this.TenantContext.TenantId)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("The enterprise application is not a cross-tenant application."));
            return $controlResult;
        }

        $this.VerifyAndReportRiskyPermissions($controlResult);

        return $controlResult;
    } 

    hidden [ControlResult] CheckEnterpiseApplicationDoesNotUsePasswordCredentials([ControlResult] $controlResult)
	{
        $spn = $this.GetMgResourceObject()
        if ($spn.ServicePrincipalType -ne 'Application')
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("SPN is not of type 'Application'."));
            return $controlResult;
        }

        $this.CheckSPNPasswordCredentials($controlResult)
        return $controlResult;
    }

    <#
        hidden [ControlResult] TBD([ControlResult] $controlResult)
        {
            $spn = $this.GetMgResourceObject()

            if ($spn.xyz)
            {
                    $controlResult.AddMessage([VerificationResult]::Failed,
                                            [MessageData]::new("Please review: $($this.SPNName)"));
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                            [MessageData]::new("PassMsg."));
            }
            return $controlResult;
        }
    #>
}