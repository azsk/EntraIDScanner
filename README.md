# EntraID Scanner

Welcome to the source code repo for the [Entra ID](https://www.microsoft.com/en-in/security/business/identity-access/microsoft-entra-id) Scanner. You can start browsing the source code by clicking on 'src' folder above. To learn more, go through the complete documentation [here](https://github.com/azsk/DevOpsKit-docs).

## Steps To install the package:
1. `Install-Module -Name PowerShellGet -RequiredVersion 2.2.5 -Scope CurrentUser -Repository PSGallery -AllowClobber`
<br>[Optional] Most systems have an older version of PowerShellGet which is not trusted anymore by the repositories.

2. `Register-PSRepository -Name [PoshTestGallery|PSGallery] -SourceLocation https://www.poshtestgallery.com/api/v2/ -InstallationPolicy Trusted`
<br>Registers a PowerShell repository.
<br>(Set the gallery name to _PSGallery_ for the prod version and _PoshTestGallery_ for dev version/bugbash purpose.)

3. `Install-module AzSKStaging.AAD -Repository PoshTestGallery -Force -AllowClobber -Scope CurrentUser`
<br>Install latest version of the module


## Running the scanner: 
1. Install the following packages if not already done before:<br>
`Install-Module -Name Az.Accounts -RequiredVersion 2.12.1 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Az.Resources -RequiredVersion 2.0.1 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.Applications -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.Users -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.Groups -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.DirectoryObjects -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>
`Install-Module -Name Microsoft.Graph.Authentication -RequiredVersion 2.12.0 -Force -Scope CurrentUser -AllowClobber`<br>


1. `ipmo AzSKStaging.AAD`
<br>Import the package

2. `Get-AzSKAADSecurityStatusTenant -TenantId <yourTenantId> -IncludeDetailedResult #Tenant scan`
<br>Tenant scan cmdlet

3. `Get-AzSKAADSecurityStatusUser -TenantId <yourTenantId> -IncludeDetailedResult -mo 10 #User owned objects scan`
<br>User owned objects scan cmdlet
