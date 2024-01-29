Set-StrictMode -Version Latest 
class User: SVTBase
{    

    User([string] $subscriptionId, [SVTResource] $svtResource): Base($subscriptionId,$svtResource) 
    {

    }

    hidden [ControlResult] CheckPATAccessLevel([ControlResult] $controlResult)
	{
        $apiURL = "https://{0}.vssps.visualstudio.com/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        if($responseObj.Count -gt 0)
        {
            $fullAccessPATList =   $responseObj | Where-Object {$_.scope -eq "app_token"}
            if(($fullAccessPATList | Measure-Object).Count -gt 0)
            {
                $fullAccessPATNames = $fullAccessPATList | Select displayName,scope 
                $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Below PAT token has full access",$fullAccessPATNames);
            }
            else {
                $AccessPATNames = $responseObj | Select displayName,scope 
                $controlResult.AddMessage([VerificationResult]::Verify,
                                        "Verify PAT token has minimum required permissions",$AccessPATNames)   
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                        "No PAT token found");
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckAltCred([ControlResult] $controlResult)
    {

        $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/dataProviders/query?api-version=5.1-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        $inputbody =  '{"contributionIds": ["ms.vss-admin-web.alternate-credentials-data-provider","ms.vss-admin-web.action-url-data-provider"]}' | ConvertFrom-Json
        $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

        if([Helpers]::CheckMember($responseObj,"data"), $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider')
        {
            if((-not $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider'.alternateCredentialsModel.basicAuthenticationDisabled) -or (-not $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider'.alternateCredentialsModel.basicAuthenticationDisabledOnAccount))
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                "Alt credential is disabled");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                "Alt credential is enabled");
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Manual,
                                                "Alt credential not found");
        }
        return $controlResult
    }

}