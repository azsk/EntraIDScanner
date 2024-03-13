using namespace Newtonsoft.Json
using namespace Microsoft.Azure.Commands.Common.Authentication.Abstractions
using namespace Microsoft.Azure.Commands.Common.Authentication
using namespace Microsoft.Azure.Management.Storage.Models
using namespace Microsoft.IdentityModel.Clients.ActiveDirectory

Set-StrictMode -Version Latest



# Represents subset of directory roles that we check against for 'AAD admin-or-not'
[Flags()]
enum PrivilegedAADRoles
{
    None = 0
    SecurityReader = 1
    UserAccountAdmin = 2
    SecurityAdmin = 4
    CompanyAdmin = 8
}

#Creates an object for our (internal) representation of a privileged role
#The term 'privileged' or 'privRole' here refers to directory roles we consider in 'admin-or-not' check
#It does not refer to AAD-PIM (at least as yet)
function New-PrivRole()
{
  param ($DisplayName, $ObjectId, $AADPrivRole)

  $privRole = new-object PSObject

  $privRole | add-member -type NoteProperty -Name DisplayName -Value $DisplayName
  $privRole | add-member -type NoteProperty -Name ObjectId -Value $ObjectId
  $privRole | add-member -type NoteProperty -Name AADPrivRole -Value $AADPrivRole

  return $privRole
}

class AccountHelper {
    static hidden [PSObject] $currentAzContext;
    static hidden [PSObject] $currentMgContext;
    static hidden [PSObject] $AADAPIAccessToken;
    static hidden [PSObject] $GraphAccessToken;

	#TODO: 'static' => most of these will get set for session! (Also statics in [Tenant] class)
	#TODO: May need to consider situations where user runs for 2 diff tenants in same session...
    static hidden [string] $tenantInfoMsg; 

    static hidden [PSObject] $currentMgUserObject;

    static hidden [CommandType] $ScanType;

    static hidden [PrivilegedAADRoles] $UserAADPrivRoles = [PrivilegedAADRoles]::None; 
    static hidden [bool] $rolesLoaded = $false;

    hidden static [PSObject] GetCurrentAzContext()
    {
        if ($null -eq [AccountHelper]::currentAzContext)
        {
            throw ([SuppressedException]::new(("Cannot call this method before getting a sign-in context!"), [SuppressedExceptionType]::InvalidOperation))
        }
        return [AccountHelper]::currentAzContext
    }

    hidden static [void] ClearTenantContext()
    {
        [AccountHelper]::currentAzContext = $null;
        [AccountHelper]::GraphAccessToken = $null;
        [AccountHelper]::tenantInfoMsg = $null;
        [AccountHelper]::UserAADPrivRoles = [PrivilegedAADRoles]::None; 
        [AccountHelper]::rolesLoaded = $false; 
        [AccountHelper]::currentMgContext = $null;
        [AccountHelper]::currentMgUserObject = $null;
    }
    
    hidden static [PSObject] GetGraphToken()
    {
        if(-not [AccountHelper]::GraphAccessToken -or [AccountHelper]::GraphAccessToken.ExpiresOn.UtcDateTime -le [DateTime]::UtcNow)
        {
            $apiToken = $null
            $azContext = $null

            try {
                #Either throws or returns non-null
                $azContext = [AccountHelper]::GetCurrentAzContext()
                if($null -ne $azContext)
                {
                    $apiToken = Get-AzAccessToken -ResourceTypeName MSGraph
                    if ($null -eq $apiToken)
                    {
                        # NOTE: This is due a unusual behaviour of Azure Powershell module, where if the user has signed-in to the exact same tenant
                        # without using the -TenantId parameter, the Get-AzAccessToken will return null.
                        # To workaround this, we are trying to force a refresh and try again
                        [AccountHelper]::RefreshAzContext($azContext.Tenant.Id);
                        $apiToken = Get-AzAccessToken -ResourceTypeName MSGraph
                    }
                }  
            }
            catch {
                throw ([SuppressedException]::new("Could not acquire graph token for the user.`r`n$_", [SuppressedExceptionType]::Generic))
            }

            [AccountHelper]::GraphAccessToken = $apiToken
        }

        return [AccountHelper]::GraphAccessToken
    }

    # Can be called with $null (when tenantId is not specified by the user)
    hidden static [PSObject] GetCurrentAzContext($desiredTenantId)
    {
        if(-not [AccountHelper]::currentAzContext)
        {
            $azContext = Get-AzContext 
            #If there's no Az ctx, or it is indeterminate (user has no Azure subscription) or the tenantId in the azCtx does not match desired tenantId
            if ($null -eq $azContext -or $null -eq $azContext.Tenant -or (-not [string]::IsNullOrEmpty($desiredTenantId) -and $azContext.Tenant.Id -ne $desiredTenantId))
            {
                $azContext = [AccountHelper]::RefreshAzContext($desiredTenantId); 
            }
            
            
            [AccountHelper]::currentAzContext = $azContext
        }
        return [AccountHelper]::currentAzContext
    }

    hidden static [psobject] RefreshAzContext($desiredTenantId)
    {
        $azContext = Get-AzContext 
        if ($azContext) #If we have a context for another tenant, disconnect.
        {
            Disconnect-AzAccount -ErrorAction Stop
        }
        #Now try to fetch a fresh context.
        try {
            if ([string]::IsNullOrEmpty($desiredTenantId))
            {
                $azureContext = Connect-AzAccount -ErrorAction Stop;
            }
            else
            {
                $azureContext = Connect-AzAccount -ErrorAction Stop -Tenant $desiredTenantId;
            }
        }
        catch {
            Write-Warning "Could not acquire Azure context interactively, will fallback to device mode";
            if ([string]::IsNullOrEmpty($desiredTenantId))
            {
                $azureContext = Connect-AzAccount -ErrorAction Stop -UseDeviceAuthentication;
            }
            else
            {
                $azureContext = Connect-AzAccount -ErrorAction Stop -Tenant $desiredTenantId -UseDeviceAuthentication;
            }
        }
        $azContext = $azureContext.Context
        [AccountHelper]::currentAzContext = $azContext
        return [AccountHelper]::currentAzContext;
    }

    hidden static [PSObject] GetCurrentMgContext()
    {
        # TODO: Remove this method once migration to microsoft graph is complete
        if ($null -eq [AccountHelper]::currentMgContext)
        {
            throw ([SuppressedException]::new(("Cannot call this method before getting a sign-in context!"), [SuppressedExceptionType]::InvalidOperation))
        }

        [AccountHelper]::RefreshMgContextToken();
        return [AccountHelper]::currentMgContext;
    }

    hidden static [PSObject] GetCurrentMgContext($desiredTenantId) #Can be $null if user did not pass one.
    {
        $currMgCtx = [AccountHelper]::currentMgContext;

        if(-not $currMgCtx -or (-not [String]::IsNullOrEmpty($desiredTenantId) -and $desiredTenantId -ne $currMgCtx.TenantId))
        {
            [AccountHelper]::ClearTenantContext();

            $mgCtx = $null;
            $mgUserObj = $null;
           
            try {
                $tenantId = $null;
                $crossTenant = $false;

                if (-not [string]::IsNullOrEmpty($desiredTenantId))
                {
                    $tenantId = $desiredTenantId;
                }

                $azContext =  [AccountHelper]::GetCurrentAzContext($desiredTenantId);
                
                if ($null -ne $azContext -and $null -ne $azContext.Tenant) #Can be $null when a user has no Azure subscriptions.
                {
                    $nativeTenantId = $azContext.Tenant.Id;
                    if ($null -eq $tenantId) #No 'desired tenant' passed in by user
                    {
                        $tenantId = $nativeTenantId;
                    }
                    else
                    {
                        #Check if desiredTenant and native tenant are diff => this user is guest in the desired tenant
                        if ($nativeTenantId -ne $desiredTenantId)
                        {
                            $crossTenant = $true;
                        }
                    }
                }

                $graphToken = ConvertTo-SecureString ([AccountHelper]::GetGraphToken().Token) -AsPlainText -Force;
                Disconnect-MgGraph;
                Connect-MgGraph -AccessToken $graphToken -NoWelcome;
                $mgCtx = Get-MgContext;

                if (-not [String]::IsNullOrEmpty($desiredTenantId) -and $desiredTenantId -ne $mgCtx.TenantId)
                {
                    Write-Error "Mismatch between desired tenantId: $desiredTenantId and tenantId from login context: $($mgCtx.TenantId).`r`nYou may have mistyped the value of 'tenantId' parameter. Please try again!";
                    throw ([SuppressedException]::new("Mismatch between desired tenantId: $desiredTenantId and tenantId from login context: $($mgCtx.TenantId)", [SuppressedExceptionType]::Generic));
                }

                $upn = $mgCtx.Account;

                if ($null -eq $upn)
                {
                    # UPN is null for personal microsoft accounts
                    $upn = $azContext.Account.Id;
                }

                if (-not $crossTenant) 
                {
                    #Try direct match first
                    $mgUserObj = Get-MgUser -Filter "UserPrincipalName eq '$upn'";
                }

                if ($null -eq $mgUserObj)
                {
                    # Personal microsoft accounts also have user_mail@user_mail.onmicrosoft.com
                    #Cross-tenant, UPN is the mangled version e.g., joe_contoso.com#desiredtenant.com
                    $upnx = (($upn -replace '@', '_')+'#')
                    $filter = "startswith(UserPrincipalName,'" + $upnx + "')";
                    $mgUserObj = Get-MgUser -Filter $filter;
                }

                if ($null -eq $mgUserObj)
                {
                    Clear-AzContext -Force;
                    throw ([SuppressedException]::new("Could not find the user in the provided tenant, are you sure the right tenant id is passed?`n$_", [SuppressedExceptionType]::Generic));
                }
            }
            catch {
                throw ([SuppressedException]::new("Could not acquire an AAD tenant context!`r`n$_", [SuppressedExceptionType]::Generic))
            }

            [AccountHelper]::ScanType = [CommandType]::AAD
            [AccountHelper]::currentMgContext = $mgCtx
            [AccountHelper]::currentMgUserObject = $mgUserObj
            [AccountHelper]::tenantInfoMsg = "AAD Tenant Info: `n`tTenantId: $($mgCtx.TenantId)"
        }

        [AccountHelper]::RefreshMgContextToken();

        return [AccountHelper]::currentMgContext
    }

    static [void] RefreshMgContextToken()
    {
        if (-not [AccountHelper]::currentMgContext)
        {
            throw ([SuppressedException]::new("Cannot call this method before getting a sign-in context!", [SuppressedExceptionType]::InvalidOperation))
        }

        if (-not [AccountHelper]::GraphAccessToken -or [AccountHelper]::GraphAccessToken.ExpiresOn.UtcDateTime -le [DateTime]::UtcNow)
        {
            Write-Information "Refreshing Microsoft Graph token for the current session..."
            $graphToken = ConvertTo-SecureString ([AccountHelper]::GetGraphToken().Token) -AsPlainText -Force;
            Connect-MgGraph -AccessToken $graphToken -NoWelcome;
            [AccountHelper]::currentMgContext = Get-MgContext;
        }
    }

    static [string] GetCurrentTenantInfo()
    {
        return [AccountHelper]::tenantInfoMsg
    }

    static [string] GetCurrentSessionUser() 
    {
        $context = [AccountHelper]::GetCurrentMgContext(); 
        if ($null -ne $context) {
            return $context.Account.Id
        }
        else {
            return "NO_ACTIVE_SESSION"
        }
    }

    static [string] GetCurrentSessionUserObjectId() 
    {
        return ([AccountHelper]::GetCurrentMgUserObject()).Id;
    }

    hidden static [PSObject] GetCurrentMgUserObject()
    {
        return [AccountHelper]::currentMgUserObject;   
    }

    hidden static [PSObject] GetEnabledPrivRolesInTenant()
    {
        #Get subset of directory level roles that have been enabled in this tenant. (Not orgs enable all roles.)
        $enabledDirRoles = [array] (Get-MgDirectoryRole)

        #$srRole = $activeRoles | ? { $_.DisplayName -eq "Security Reader"}
        
        $apr = @()
        $enabledDirRoles | % {
            $ar = $_
        
            switch ($ar.DisplayName)
            {
                'Security Reader' { 
                    $apr += New-PrivRole -DisplayName 'Security Reader' -ObjectId $ar.Id -AADPrivRole ([PrivilegedAADRoles]::SecurityReader)
                }
        
                'User Account Administrator' { 
                    $apr += New-PrivRole -DisplayName 'User Account Administrator' -ObjectId $ar.Id -AADPrivRole ([PrivilegedAADRoles]::UserAccountAdmin)
                }
                 
                'Security Administrator' {
                    $apr += New-PrivRole -DisplayName 'Security Administrator' -ObjectId $ar.Id -AADPrivRole ([PrivilegedAADRoles]::SecurityAdmin)
                }
        
                'Company Administrator' {
                    $apr += New-PrivRole -DisplayName 'Company Administrator' -ObjectId $ar.Id -AADPrivRole ([PrivilegedAADRoles]::CompanyAdmin)
                }
            }
        }
        return $apr        
    } 

    #Returns a bit flag representing all roles we consider 'admin-like' that the user is currently a member of. 
    #TODO: This only uses 'permanent' membership checks currently. Need to augment for PIM.
    static [PrivilegedAADRoles] GetUserPrivTenantRoles([String] $uid)
    {
        if ([AccountHelper]::rolesLoaded -eq $false)
        {
            $upr = [PrivilegedAADRoles]::None
            $apr = [AccountHelper]::GetEnabledPrivRolesInTenant()
            $apr | % {
                $pr = $_
                #Write-Host "$pr.AADPrivRole"
                $roleMembers = [array] (Get-MgDirectoryRoleMember -DirectoryRoleId $pr.ObjectId)
                #Write-Host "Count: $($roleMembers.Count)"
                if($roleMembers)
                {
                    $roleMembers | % { if ($_.Id -eq $uid) {$upr = $upr -bor $pr.AADPrivRole}}
                }
                
            }    

            [AccountHelper]::UserAADPrivRoles = $upr
            [AccountHelper]::rolesLoaded = $true
        }
        return [AccountHelper]::UserAADPrivRoles
    }

    #Is user a member of any directory role we consider 'admin-equiv.'?
    #Note: #TODO: This does not check for PIM-based role membership yet.
    static [bool] IsUserInAPermanentAdminRole()
    {
        $uid = ([AccountHelper]::GetCurrentMgUserObject()).Id
        $upr = [AccountHelper]::GetUserPrivTenantRoles($uid)
        return ($upr -ne [PrivilegedAADRoles]::None) 
    }


    hidden static [PSObject] GetCurrentAADAPIToken()
    {
        if(-not [AccountHelper]::AADAPIAccessToken)
        {
            $apiToken = $null
            
            $AADAPIGuid = [Constants]::AADAPIGuid

            #Try leveraging Azure context if available
            try {
                #Either throws or returns non-null
                $azContext = [AccountHelper]::GetCurrentAzContext()
                $tenantId = $null
                if ($null -ne $azContext.Tenant) #happens if user does not have any Azure subs.
                {
                    $tenantId = $azContext.Tenant.Id
                }
                else {
                    $tenantId = ([AccountHelper]::GetCurrentMgContext()).TenantId 
                }
                $apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $tenantId, $null, "Never", $null, $AADAPIGuid)
            }
            catch {
                Write-Warning "Could not get AAD API token for: $AADAPIGuid."
                throw ([SuppressedException]::new("Could not get AAD API token for: $AADAPIGuid.", [SuppressedExceptionType]::Generic))
            }

            [AccountHelper]::AADAPIAccessToken = $apiToken
            #TODO move to detailed log: Write-Host("Successfully acquired API access token for $AADAPIGuid")
		}
        return [AccountHelper]::AADAPIAccessToken
    }

    #TODO: Review calls to this. Should we have an AAD-version for it? Or just remove...
    static [string] GetAccessToken([string] $resourceAppIdUri, [string] $tenantId) 
    {
        return [AccountHelper]::GetAzureDevOpsAccessToken();
    }

    static [string] GetAzureDevOpsAccessToken()
    {
        # TODO: Handlle login
        if([AccountHelper]::currentAzureDevOpsContext)
        {
            return [AccountHelper]::currentAzureDevOpsContext.AccessToken
        }
        else
        {
            return $null
        }
    }

    static [string] GetAccessToken([string] $resourceAppIdUri) 
    {
        if([AccountHelper]::ScanType -eq [CommandType]::AzureDevOps)
        {
            return [AccountHelper]::GetAzureDevOpsAccessToken()
        }
        else {
            return [AccountHelper]::GetAccessToken($resourceAppIdUri, "");    
        }
        
    }

    static [string] GetAccessToken()
    {
        if([AccountHelper]::ScanType -eq [CommandType]::AzureDevOps)
        {
            return [AccountHelper]::GetAzureDevOpsAccessToken()
        }
        else {
            #TODO : Fix ResourceID
            return [AccountHelper]::GetAccessToken("", "");    
        }
    }
}
