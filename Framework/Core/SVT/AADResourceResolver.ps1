Set-StrictMode -Version Latest

class AADResourceResolver: Resolver
{
    [SVTResource[]] $SVTResources = @();
    [string] $ResourcePath;
    [string] $tenantId;
    [int] $SVTResourcesFoundCount=0;
    [bool] $scanTenant;
    [int] $MaxObjectsToScan;
    [int] $BatchThreshold;
    [bool] $ShouldBatchScan;
    [string[]] $ObjectTypesToScan;
    hidden static [string[]] $AllTypes = @("AppRegistration", "Device", "Group", "EnterpriseApplication", "User");
    hidden [PsCustomObject] $BatchCounters = [PSCustomObject]@{
        App = 0
        SPN = 0
        Device = 0
        Group = 0
        User = 0
    }

    AADResourceResolver([string]$tenantId, [bool] $bScanTenant): Base($tenantId)
	{
        if ([string]::IsNullOrEmpty($tenantId))
        {
            $this.tenantId = ([AccountHelper]::GetCurrentAADContext()).TenantId
        }
        else 
        {
            $this.tenantId = $tenantId
        }
        $this.scanTenant = $bScanTenant
        #TODO: See if we can read this from some settings file.
        $this.BatchThreshold = 5000;
    }

    [void] SetScanParameters([string[]] $objTypesToScan, $maxObj)
    {
        $this.MaxObjectsToScan = $maxObj
        
        if ($objTypesToScan.Contains("All"))
        {
            if ($objTypesToScan.Count -ne 1)
            {
                throw ([SuppressedException]::new("The objectType 'All' cannot be used in combination with other types.", [SuppressedExceptionType]::InvalidOperation))
            }
            $this.ObjectTypesToScan = [AADResourceResolver]::AllTypes
        }
        elseif ($objTypesToScan.Contains("None"))
        {
            if ($objTypesToScan.Count -ne 1)
            {
                throw ([SuppressedException]::new("The objectType 'None' cannot be used in combination with other types.", [SuppressedExceptionType]::InvalidOperation))
            }
            $this.ObjectTypesToScan = $objTypesToScan
        }
        else
        {
            $this.ObjectTypesToScan = $objTypesToScan
        }

        $this.ShouldBatchScan = ($this.MaxObjectsToScan -le 0 -or $this.MaxObjectsToScan -gt $this.BatchThreshold);
    }

    [bool] NeedToScanType([string] $objType)
    {
        return $this.ObjectTypesToScan -contains $objType
    }

    [void] ClearResources()
    {
        $this.SVTResources = @();
    }

    [void] LoadResourcesForScan()
	{
        $tenantInfoMsg = [AccountHelper]::GetCurrentTenantInfo();
        #Write-Host -ForegroundColor Green $tenantInfoMsg  #TODO: Need to do with PublishCustomMessage...just before #-of-resources...etc.?
        $this.PublishCustomMessage([Constants]::DoubleDashLine + "`r`n$tenantInfoMsg`r`n" + [Constants]::DoubleDashLine, [MessageType]::Update )

        #TODO: TBD - for use later...
        $bAdmin = [AccountHelper]::IsUserInAPermanentAdminRole();

        #scanTenant is used to determine is the scan is tenant wide or just within the scope of the current (logged-in) user.
        if ($this.scanTenant)
        {
            $svtResource = [SVTResource]::new();
            $svtResource.ResourceName = $this.tenantContext.TenantName;
            $svtResource.ResourceType = "AAD.Tenant";
            $svtResource.ResourceId = $this.tenantId
            $svtResource.ResourceTypeMapping = ([SVTMapping]::AADResourceMapping |
                                            Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
                                            Select-Object -First 1)
            $this.SVTResources +=$svtResource
        }

        $currUser = [AccountHelper]::GetCurrentSessionUserObjectId();

        $userOwnedObjects = @()

        try {  #BUGBUG: Investigate why this crashes in the Live tenant (even if user-created-objects exist...which should show up as 'user-owned' by default!) 
            $userOwnedObjects = [array] (Get-AzureADUserOwnedObject -ObjectId $currUser)
        }
        catch { #As a workaround, we take user-created objects, which seems to work (strange!)
            $userCreatedObjects = [array] (Get-AzureADUserCreatedObject -ObjectId $currUser)
            $userOwnedObjects = $userCreatedObjects
        }
        #TODO Explore delta between 'user-created' v. 'user-owned' for Apps/SPNs

        $maxObj = $this.MaxObjectsToScan;

        if ($this.NeedToScanType("AppRegistration"))
        {
            $appObjects = @()
            if ($this.scanTenant)
            {
                if ($this.ShouldBatchScan)
                {
                    $appObjects = [array] (Get-AzADApplication -First $this.BatchThreshold -Skip $this.BatchCounters.App);
                    $this.BatchCounters.App += $appObjects.Count;
                }
                else
                {
                    $appObjects = [array] (Get-AzADApplication -First $maxObj);
                }
            }
            else {
                $appObjects = [array] ($userOwnedObjects | ?{$_.ObjectType -eq 'Application'})
            }

            $appTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.AppRegistration' } |
                Select-Object -First 1)

            #TODO: Set to 3 for preview release. A user can use a larger value if they want via the 'MaxObj' cmdlet param.
            $maxObj = $this.MaxObjectsToScan

            $nObj = $maxObj
            foreach ($obj in $appObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file. 
                #TODO: If rgName == "" then all LOGs end up in root folder alongside CSV, README.txt. May need to have a reasonable 'mock' RGName.
                $svtResource.ResourceType = "AAD.AppRegistration";
                $svtResource.ResourceId = $obj.ObjectId     
                $svtResource.ResourceTypeMapping = $appTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            }
        }

        if ($this.NeedToScanType("EnterpriseApplication"))
        {
            $spnObjects = @()
            if ($this.scanTenant)
            {
                if ($this.ShouldBatchScan)
                {
                    $spnObjects = [array] (Get-AzADServicePrincipal -First $this.BatchThreshold -Skip $this.BatchCounters.SPN);
                    $this.BatchCounters.SPN += $spnObjects.Count;
                }
                else
                {
                    $spnObjects = [array] (Get-AzADServicePrincipal -First $maxObj);
                }
            }
            else {
                $spnObjects = [array] ($userOwnedObjects | ?{$_.ObjectType -eq 'ServicePrincipal'})
            }
            
            $spnTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.EnterpriseApplication' } |
                Select-Object -First 1)

            $nObj = $maxObj
            foreach ($obj in $spnObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.EnterpriseApplication";
                $svtResource.ResourceId = $obj.ObjectId     
                $svtResource.ResourceTypeMapping = $spnTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            }   #TODO odd that above query does not show user created 'Group' objects.
        }

        if ($this.NeedToScanType("Device"))
        {
            $deviceObjects = @()
            if ($this.scanTenant)
            {
                if ($this.ShouldBatchScan)
                {
                    $deviceObjects = [array] (Get-MgDevice -Top  $this.BatchThreshold -Skip $this.BatchCounters.Device);
                    $this.BatchCounters.Device += $deviceObjects.Count;
                }
                else
                {
                    $deviceObjects = [array] (Get-MgDevice -Top  $maxObj);
                }
            }
            else {
                $DeviceObjects = [array] (Get-AzureADUserOwnedDevice -ObjectId $currUser)
            }
            
            $deviceTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.Device' } |
                Select-Object -First 1)

            $nObj = $maxObj
            foreach ($obj in $deviceObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.Device";
                $svtResource.ResourceId = $obj.ObjectId     
                $svtResource.ResourceTypeMapping = $deviceTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            }   #TODO odd that above query does not show user created 'Group' objects.
        }

    
        if ($this.NeedToScanType("User"))
        {
            $userObjects = @()
            if ($this.scanTenant)
            {
                if ($this.ShouldBatchScan)
                {
                    $userObjects = [array] (Get-AzADUser -First $this.BatchThreshold -Skip $this.BatchCounters.User);
                    $this.BatchCounters.User += $userObjects.Count;
                }
                else
                {
                    $userObjects = [array] (Get-AzureADUser -Top $maxObj)
                }
            }
            else {
                $userObjects = [array] (Get-AzureADUser -ObjectId $currUser)
            }

            $userTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.User' } |
                Select-Object -First 1)

            $nObj = $maxObj
            foreach ($obj in $userObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.User";
                $svtResource.ResourceId = $obj.ObjectId     
                $svtResource.ResourceTypeMapping = $userTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            } 
        }


        if ($this.NeedToScanType("Group"))
        {
            $grpObjects = @()
            if ($this.scanTenant)
            {
                if ($this.ShouldBatchScan)
                {
                    $grpObjects = [array] (Get-AzADGroup -First $this.BatchThreshold -Skip $this.BatchCounters.Group);
                    $this.BatchCounters.Group += $grpObjects.Count;
                }
                else
                {
                    $grpObjects = [array] (Get-AzADGroup -First $maxObj)
                }
            }
            else {
                $grpObjects = [array] ($userOwnedObjects | ?{$_.ObjectType -eq 'Group'})
            }

            $grpTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.Group' } |
                Select-Object -First 1)

            $nObj = $maxObj
            foreach ($obj in $grpObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.Group";
                $svtResource.ResourceId = $obj.ObjectId     
                $svtResource.ResourceTypeMapping = $grpTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            }   #TODO Why does this not show user created 'Group' objects in live tenant?
        }

        $this.SVTResourcesFoundCount = $this.SVTResources.Count
    }
}