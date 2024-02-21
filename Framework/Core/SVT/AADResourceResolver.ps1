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

    hidden static [string[]] $AllTypes = @("AppRegistration", "EnterpriseApplication");

    hidden [int] $hardStopLimit;
    hidden [bool] $isTenantScanned = $false;


    AADResourceResolver([string]$tenantId, [bool] $bScanTenant): Base($tenantId)
	{
        if ([string]::IsNullOrEmpty($tenantId))
        {
            $this.tenantId = ([AccountHelper]::GetCurrentMgContext()).TenantId
        }
        else 
        {
            $this.tenantId = $tenantId
        }
        $this.scanTenant = $bScanTenant
        #TODO: See if we can read this from some settings file.
        $this.BatchThreshold = 999;
        $this.hardStopLimit = 15000; 
    }

    [void] SetScanParameters([string[]] $objTypesToScan, $maxObj)
    { 
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

        $this.ShouldBatchScan = ($maxObj -le 0 -or $maxObj -gt $this.BatchThreshold);
        if ($maxObj -le 0 -or $maxObj -gt $this.hardStopLimit)
        {
            $this.MaxObjectsToScan = $this.hardStopLimit
        }
        else
        {
            $this.MaxObjectsToScan = $maxObj
        }
    }

    [bool] NeedToScanType([string] $objType)
    {
        return $this.ObjectTypesToScan -contains $objType
    }

    [void] ClearResources()
    {
        $this.SVTResources = @();
    }

    [string] ExtractDisplayNameFromResource([PsCustomObject] $resource)
    {
        if($this.scanTenant)
        {
            return $resource.DisplayName;
        }
        else
        {
           return $resource.AdditionalProperties["displayName"];
        }
    }

    [void] LoadResourcesForScan()
	{
        $tenantInfoMsg = [AccountHelper]::GetCurrentTenantInfo();
        #Write-Host -ForegroundColor Green $tenantInfoMsg  #TODO: Need to do with PublishCustomMessage...just before #-of-resources...etc.?
        $this.PublishCustomMessage([Constants]::DoubleDashLine + "`r`n$tenantInfoMsg`r`n" + [Constants]::DoubleDashLine, [MessageType]::Update )

        #TODO: TBD - for use later...
        $bAdmin = [AccountHelper]::IsUserInAPermanentAdminRole();

        #scanTenant is used to determine is the scan is tenant wide or just within the scope of the current (logged-in) user.
        # if ($this.scanTenant -and !$this.isTenantScanned)
        # {
        #     $svtResource = [SVTResource]::new();
        #     $svtResource.ResourceName = $this.tenantContext.TenantName;
        #     $svtResource.ResourceType = "AAD.Tenant";
        #     $svtResource.ResourceId = $this.tenantId
        #     $svtResource.ResourceTypeMapping = ([SVTMapping]::AADResourceMapping |
        #                                     Where-Object { $_.ResourceType -eq $svtResource.ResourceType } |
        #                                     Select-Object -First 1)
        #     $this.SVTResources +=$svtResource
        #     $this.isTenantScanned = $true;
        # }

        $currUser = [AccountHelper]::GetCurrentSessionUserObjectId();

        $userOwnedObjects = @()

        try {  #BUGBUG: Investigate why this crashes in the Live tenant (even if user-created-objects exist...which should show up as 'user-owned' by default!) 
            if ($this.ShouldBatchScan)
            {
                $userOwnedObjects = [array] (Get-MgUserOwnedObject -UserId $currUser -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan);
            }
            else
            {
                $userOwnedObjects = [array] (Get-MgUserOwnedObject -UserId $currUser -Top $this.MaxObjectsToScan);   
            }
        }
        catch { #As a workaround, we take user-created objects, which seems to work (strange!)
            if ($this.ShouldBatchScan)
            {
                $userCreatedObjects = [array] (Get-MgUserCreatedObject -UserId $currUser -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan);
                $this.BatchCounters.UserOwnedObjects += $userCreatedObjects.Count;
            }
            else
            {
                $userCreatedObjects = [array] (Get-MgUserCreatedObject -UserId $currUser -Top $this.MaxObjectsToScan);   
            }
            $userOwnedObjects = $userCreatedObjects
        }
        #TODO Explore delta between 'user-created' v. 'user-owned' for Apps/SPNs

        if ($this.NeedToScanType("AppRegistration"))
        {
            $appObjects = @()
            if ($this.scanTenant)
            {
                if($this.ShouldBatchScan)
                {
                    Write-Host "You have requested for a full tenant scan. Loading resources will take some time. Since this is a preview version, we have added a hard stop to scan first 15K resources." -ForegroundColor "Yello"
                }
                if ($this.ShouldBatchScan)
                {
                    $appObjects = [array] (Get-MgApplication -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan -Property Id, DisplayName);
                }
                else
                {
                    $appObjects = [array] (Get-MgApplication -Top $this.MaxObjectsToScan -Property Id, DisplayName);
                }
            }
            else {
                $appObjects = [array] ($userOwnedObjects | Where-Object {$_.AdditionalProperties."@odata.type" -eq '#microsoft.graph.application'})
            }

            $appTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.AppRegistration' } |
                Select-Object -First 1)

            $nObj = $this.MaxObjectsToScan
            foreach ($obj in $appObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $this.ExtractDisplayNameFromResource($obj);
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file. 
                #TODO: If rgName == "" then all LOGs end up in root folder alongside CSV, README.txt. May need to have a reasonable 'mock' RGName.
                $svtResource.ResourceType = "AAD.AppRegistration";
                $svtResource.ResourceId = $obj.Id     
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
                    $spnObjects = [array] (Get-MgServicePrincipal -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan -Property Id, DisplayName);
                }
                else
                {
                    $spnObjects = [array] (Get-MgServicePrincipal -Top $this.MaxObjectsToScan -Property Id, DisplayName);
                }
            }
            else {
                $spnObjects = [array] ($userOwnedObjects | Where-Object {$_.AdditionalProperties."@odata.type" -eq '#microsoft.graph.servicePrincipal'})
            }
            
            $spnTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.EnterpriseApplication' } |
                Select-Object -First 1)

            $nObj = $this.MaxObjectsToScan
            foreach ($obj in $spnObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $this.ExtractDisplayNameFromResource($obj);
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.EnterpriseApplication";
                $svtResource.ResourceId = $obj.Id     
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
                    $deviceObjects = [array] (Get-MgDevice -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan -Property Id, DisplayName);
                }
                else
                {
                    $deviceObjects = [array] (Get-MgDevice -Top $this.MaxObjectsToScan -Property Id, DisplayName);
                }
            }
            else {
                if ($this.ShouldBatchScan)
                {
                    $DeviceObjects = [array] (Get-MgUserOwnedDevice -UserId $currUser -PageSize)
                }
                else
                {
                    $DeviceObjects = [array] (Get-MgUserOwnedDevice -UserId $currUser -Top $this.MaxObjectsToScan)
                }
            }
            
            $deviceTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.Device' } |
                Select-Object -First 1)

            $nObj = $this.MaxObjectsToScan
            foreach ($obj in $deviceObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $this.ExtractDisplayNameFromResource($obj)
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.Device";
                $svtResource.ResourceId = $obj.Id     
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
                    $userObjects = [array] (Get-MgUser -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan -Property Id, DisplayName);
                }
                else
                {
                    $userObjects = [array] (Get-MgUser -Top $this.MaxObjectsToScan -Property Id, DisplayName)
                }
            }
            else {
                $userObjects = [array] (Get-MgUser -UserId $currUser -Property Id, DisplayName)
            }

            $userTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.User' } |
                Select-Object -First 1)

            $nObj = $this.MaxObjectsToScan
            foreach ($obj in $userObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $obj.DisplayName
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.User";
                $svtResource.ResourceId = $obj.Id     
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
                    $grpObjects = [array] (Get-MgGroup -PageSize $this.BatchThreshold -All -Limit $this.MaxObjectsToScan -Property Id, DisplayName);
                }
                else
                {
                    $grpObjects = [array] (Get-MgGroup -Top $this.MaxObjectsToScan -Property Id, DisplayName)
                }
            }
            else {
                $grpObjects = [array] ($userOwnedObjects | Where-Object {$_.AdditionalProperties."@odata.type" -eq '#microsoft.graph.group'})
            }

            $grpTypeMapping = ([SVTMapping]::AADResourceMapping |
                Where-Object { $_.ResourceType -eq 'AAD.Group' } |
                Select-Object -First 1)

            $nObj = $this.MaxObjectsToScan;
            foreach ($obj in $grpObjects) {
                $svtResource = [SVTResource]::new();
                $svtResource.ResourceName = $this.ExtractDisplayNameFromResource($obj);;
                $svtResource.ResourceGroupName = ""  #If blank, the column gets skipped in CSV file.
                $svtResource.ResourceType = "AAD.Group";
                $svtResource.ResourceId = $obj.Id     
                $svtResource.ResourceTypeMapping = $grpTypeMapping   
                $this.SVTResources +=$svtResource
                if (--$nObj -eq 0) { break;} 
            }   #TODO Why does this not show user created 'Group' objects in live tenant?
        }

        $this.SVTResourcesFoundCount = $this.SVTResources.Count;
    }
}