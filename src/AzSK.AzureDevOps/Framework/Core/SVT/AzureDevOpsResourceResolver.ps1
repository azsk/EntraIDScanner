Set-StrictMode -Version Latest

class AzureDevOpsResourceResolver: Resolver
{
    [SVTResource[]] $SVTResources = @();
    [string] $ResourcePath;
    [string] $organizationName
    hidden [string[]] $ProjectNames = @();
    hidden [string[]] $BuildNames = @();
    hidden [string[]] $ReleaseNames = @();
    [int] $SVTResourcesFoundCount=0;
    AzureDevOpsResourceResolver([string]$organizationName,$ProjectNames,$BuildNames,$ReleaseNames): Base($organizationName)
	{
        $this.organizationName = $organizationName

        if(-not [string]::IsNullOrEmpty($ProjectNames))
        {
			$this.ProjectNames += $this.ConvertToStringArray($ProjectNames);

			if ($this.ProjectNames.Count -eq 0)
			{
				throw [SuppressedException] "The parameter 'ProjectNames' does not contain any string."
			}
        }	

        if(-not [string]::IsNullOrEmpty($BuildNames))
        {
			$this.BuildNames += $this.ConvertToStringArray($BuildNames);
			if ($this.BuildNames.Count -eq 0)
			{
				throw [SuppressedException] "The parameter 'BuildNames' does not contain any string."
			}
        }

        if(-not [string]::IsNullOrEmpty($ReleaseNames))
        {
			$this.ReleaseNames += $this.ConvertToStringArray($ReleaseNames);
			if ($this.ReleaseNames.Count -eq 0)
			{
				throw [SuppressedException] "The parameter 'ReleaseNames' does not contain any string."
			}
        }
    }

    [void] LoadAzureResources()
	{
        
        #Call APIS for Organization,User/Builds/Releases/ServiceConnections 
        #Select Org/User by default...
        $svtResource = [SVTResource]::new();
        $svtResource.ResourceName = $this.organizationName;
        $svtResource.ResourceType = "AzureDevOps.Organization";
        $svtResource.ResourceId = "Organization/$($this.organizationName)/"
        $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                        Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                        Select-Object -First 1)
        $this.SVTResources +=$svtResource

        $svtResource = [SVTResource]::new();
        $svtResource.ResourceName = $this.organizationName;
        $svtResource.ResourceType = "AzureDevOps.User";
        $svtResource.ResourceId = "Organization/$($this.organizationName)/User"
        $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                        Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                        Select-Object -First 1)
        $this.SVTResources +=$svtResource

        #Get project resources
        $apiURL = "https://dev.azure.com/{0}/_apis/projects?api-version=4.1" -f $($this.SubscriptionContext.SubscriptionName);
        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL) ;

        $responseObj  | Where-Object { $this.ProjectNames.Count -eq 0 -or $this.ProjectNames -contains $_.name  } | ForEach-Object {
            $projectName = $_.name
            $svtResource = [SVTResource]::new();
            $svtResource.ResourceName = $_.name;
            $svtResource.ResourceGroupName = $this.organizationName
            $svtResource.ResourceType = "AzureDevOps.Project";
            $svtResource.ResourceId = $_.url
            $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                            Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                            Select-Object -First 1)
            
            $this.SVTResources +=$svtResource

            $serviceEndpointURL = "https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?api-version=4.1-preview.1" -f $($this.organizationName),$($projectName);
            $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)
            
            if(([Helpers]::CheckMember($serviceEndpointObj,"count") -and $serviceEndpointObj[0].count -gt 0) -or  (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0],"name")))
            {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = "ServiceConnections";
                $svtResource.ResourceGroupName =$_.name;
                $svtResource.ResourceType = "AzureDevOps.ServiceConnection";
                $svtResource.ResourceId = "Organization/$($this.organizationName)/Project/ServiceConnection"
                $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                                Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                                Select-Object -First 1)
                $this.SVTResources +=$svtResource
            }

            $buildDefnURL = "https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=4.1" -f $($this.SubscriptionContext.SubscriptionName), $_.name;
            $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL) 
            if(([Helpers]::CheckMember($buildDefnsObj,"count") -and $buildDefnsObj[0].count -gt 0) -or  (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0],"name")))
            {
                $buildDefnsObj | Where-Object { $this.BuildNames.Count -eq 0 -or $this.BuildNames -contains $_.name  } | ForEach-Object {
                    $svtResource = [SVTResource]::new();
                    $svtResource.ResourceName = $_.name;
                    $svtResource.ResourceGroupName =$_.project.name;
                    $svtResource.ResourceType = "AzureDevOps.Build";
                    $svtResource.ResourceId = $_.url
                    $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                                    Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                                    Select-Object -First 1)
                    $this.SVTResources +=$svtResource
                }
            }       

            $releaseDefnURL = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=4.1-preview.3" -f $($this.SubscriptionContext.SubscriptionName), $_.name;
            $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL);
            if(([Helpers]::CheckMember($releaseDefnsObj,"count") -and $releaseDefnsObj[0].count -gt 0) -or  (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0],"name")))
            {
                $releaseDefnsObj | Where-Object { $this.ReleaseNames.Count -eq 0 -or $this.ReleaseNames -contains $_.name  } | ForEach-Object {
                    $svtResource = [SVTResource]::new();
                    $svtResource.ResourceName = $_.name;
                    $svtResource.ResourceGroupName =$projectName;
                    $svtResource.ResourceType = "AzureDevOps.Release";
                    $svtResource.ResourceId = $_.url
                    $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKDevOpsResourceMapping |
                                                    Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                                    Select-Object -First 1)
                    $this.SVTResources +=$svtResource
                }
            }        
        }
        $this.SVTResourcesFoundCount = $this.SVTResources.Count
    }
}