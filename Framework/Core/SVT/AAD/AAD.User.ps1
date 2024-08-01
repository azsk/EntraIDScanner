Set-StrictMode -Version Latest 
class User: SVTBase
{    
    hidden [PSObject] $MgResourceObject;

    User([string] $tenantId, [SVTResource] $svtResource): Base($tenantId, $svtResource) 
    {
        $objId = $svtResource.ResourceId
        $this.MgResourceObject = Get-MgUser -UserId $objId    
    }

    hidden [PSObject] GetMgResourceObject()
    {
        return $this.MgResourceObject;
    }

    hidden [ControlResult] CheckPasswordExpiration([ControlResult] $controlResult)
	{
        $u = $this.GetMgResourceObject();
        $pp = $u.PasswordPolicies
        if($pp -ne $null -and $pp -match 'DisablePasswordExpiration' ) 
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                "User [$($u.DisplayName)] has 'password expiration' disabled. Please review!");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "User does not have password expiration disabled.");
        }        
        return $controlResult;
    }

    hidden [ControlResult] CheckStrongPassword([ControlResult] $controlResult)
	{
        $u = $this.GetMgResourceObject();
        $pp = $u.PasswordPolicies
        if($pp -ne $null -and $pp -match 'DisableStrongPassword' ) 
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                "User [$($u.DisplayName)] has 'strong password' disabled. Please review!");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "User does not have 'strong password' disabled.");
        }
        return $controlResult;
    }


    hidden [ControlResult] CheckUserDirSyncSetting([ControlResult] $controlResult)
	{
        $u = $this.GetMgResourceObject();

        #Flag users that were created 'cloud-only' if the tenant is enabled for dir-sync.
        if ( [Tenant]::IsDirectorySyncEnabled() -and (-not $u.DirSyncEnabled -eq $true)) 
        {
            $controlResult.AddMessage([VerificationResult]::Verify,
                                "User [$($u.DisplayName)] appears to be a 'cloud only' user although you have dir-sync enabled for the tenant. Please review!");
        }
        elseif ( -not [Tenant]::IsDirectorySyncEnabled() -and ($u.DirSyncEnabled -eq $true)) 
        {
            $controlResult.AddMessage([VerificationResult]::Verify,
                                "User [$($u.DisplayName)] has DirSync flag set to true even though dir-sync enabled is not enabled for the tenant. Please review!");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "User object dir-sync setting matches tenant settings .");
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckGuestSelfServiceSignupFlow([ControlResult] $controlResult)
	{
        # Connect-MgGraph -Scopes "Policy.Read.All"
        # (This need the admin access of the tenant and it is necessary to run this command before running the below commands)

        #Get the self-service sign up policy
        $property=Get-MgBetaPolicyAuthenticationFlowPolicy | Select-Object selfServiceSignUp
        #Check if self-service sign up is enabled
        if($property.SelfServiceSignUp.IsEnabled -eq $true)
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                "Guest self-service sign up via user flows is enabled. Please review!");
        }
        #If self-service sign up is disabled
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "Guest self-service sign up via user flows is disabled.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckGuestInviteSettings([ControlResult] $controlResult)
	{
        # Check if anyone in the organization is allowed to invite guests    
        $inviteRestrictions=Get-MgBetaPolicyAuthorizationPolicy | Select-Object allowInvitesFrom
        #If everyone is allowed to invite guests
        if($inviteRestrictions.AllowInvitesFrom -eq "everyone")
        {
            $controlResult.AddMessage([VerificationResult]::Failed,
                                "Anyone in the organization is allowed to invite guests. Please review!");
        }
        #If only specific people are allowed to invite guests
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                "Only specific people are allowed to invite guests.");
        }
        return $controlResult;
    }
}
