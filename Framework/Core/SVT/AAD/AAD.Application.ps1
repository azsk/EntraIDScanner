Set-StrictMode -Version Latest 
class Application: SVTBase
{    
	hidden [PSObject] $ResourceObject;
    hidden [hashtable] $DNSCache = @{};

    Application([string] $tenantId, [SVTResource] $svtResource): Base($tenantId,$svtResource) 
    {

        $objId = $svtResource.ResourceId
        $this.ResourceObject = Get-AzureADObjectByObjectId -ObjectIds $objId
    }

    hidden [PSObject] GetResourceObject()
    {
        return $this.ResourceObject;
    }

    hidden [bool] IsURLDangling([string] $uri)
    {
        if($this.DNSCache.ContainsKey($uri))
        {
            return $this.DNSCache[$uri];
        }
        $ownership = Resolve-DnsName -Name $uri;
        if($null -eq $ownership)
        {
            $this.DNSCache[$uri] = $false;
        }
        else
        {
            $this.DNSCache[$uri] = $true;
        }
        return $this.DNSCache[$uri];
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

    hidden [ControlResult] CheckRedirectURIsWithWilcard([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()
        if($null -eq $app.ReplyURLs -or $app.ReplyURLs.Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
            "No redirect URLs were found.");
        }
        else
        {
            $urlsWithWildcard = @()
            foreach ($url  in $app.ReplyURLs)
            {
                if ($url.Contains("*"))
                {
                    $urlsWithWildcard += $url
                }
            }

            if ($urlsWithWildcard.Count -eq 0)
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                        "No redirect URLs with wildcards were found.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed,
                "Following redirect URLs with wildcard characters were found: ", $($urlsWithWildcard | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $urlsWithWildcard);
            }
        }
        

        return $controlResult;
    }

    hidden [ControlResult] CheckDanglingRedirectURIs([ControlResult] $controlResult)
    {
        $app = $this.GetResourceObject()
        if($null -eq $app.ReplyURLs -or $app.ReplyURLs.Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
            "No redirect URLs were found.");
        }
        else
        {
            $danglingUrls = @()
            
            foreach ($url  in $app.ReplyURLs)
            {
                $parsedUrl = $url
                if($parsedUrl -match "http://")
                {
                    $parsedUrl = ($url -split "http://" -split "/")[1]
                }
                elseif($parsedUrl -match "https://")
                {
                    $parsedUrl = ($url -split "https://" -split "/")[1]
                }
                else 
                {
                    continue;
                }

                if ($parsedUrl.Contains("*"))
                {
                    $danglingUrls += $url
                }
                else 
                {
                    $isUrlDangling = $this.IsURLDangling($parsedUrl);
                    if(!$isUrlDangling)
                    {
                        $danglingUrls += $url
                    }
                }
            }

            if ($danglingUrls.Count -eq 0)
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                        "No dangling redirect URLs were found.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed,
                "Following redirect URLs with no ownership were found: ", $($danglingUrls | Format-Table -AutoSize | Out-String));
                $controlResult.DetailedResult = (ConvertTo-Json $danglingUrls);
            }
        }
        

        return $controlResult;
    }

}
