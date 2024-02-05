Set-StrictMode -Version Latest 
class ServicePrincipal: SVTBase
{    
    hidden [PSObject] $ResourceObject;
    hidden [String] $SPNName;
    hidden [psobject] $RiskyPermissions;

    ServicePrincipal([string] $tenantId, [SVTResource] $svtResource): Base($tenantId, $svtResource) 
    {
        #$this.GetResourceObject();
        $objId = $svtResource.ResourceId

        $this.ResourceObject = Get-AzureADObjectByObjectId -ObjectIds $objId
        $this.SPNName = $this.ResourceObject.DisplayName
        $this.RiskyPermissions = [Helpers]::LoadOfflineConfigFile('Azsk.AAD.RiskyPermissions.json', $true);
    }

    hidden [PSObject] GetResourceObject()
    {
        return $this.ResourceObject;
    }

    hidden [ControlResult] CheckSPNPasswordCredentials([ControlResult] $controlResult)
	{
        $spn = $this.GetResourceObject()

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
        $spn = $this.GetResourceObject()

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
        $spn = $this.GetResourceObject()

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
        $app = $this.GetResourceObject()

        $owners = [array] (Get-AzureADServicePrincipalOwner -ObjectId $app.ObjectId)
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

    hidden [ControlResult] CheckEnterpriseAppUsesMiniminalPermissions([ControlResult] $controlResult)
    {
        $spn = $this.GetResourceObject();
        $appRoleAssignmentGroups = (Get-AzureADServicePrincipalAppRoleAssignment -ObjectId $spn.ObjectId) | Group-Object -Property ResourceId
        $appRoleOauth2PermissionGrants = (Get-AzureADServicePrincipalOauth2PermissionGrant -ObjectId $spn.ObjectId) | Group-Object -Property ResourceId
        
       
        return $controlResult;
    }

    <#
        hidden [ControlResult] TBD([ControlResult] $controlResult)
        {
            $spn = $this.GetResourceObject()

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