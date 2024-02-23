# EntraID Scanner

Welcome to the source code repo for the [Entra ID](https://www.microsoft.com/en-in/security/business/identity-access/microsoft-entra-id) Scanner. You can start browsing the source code by clicking on 'src' folder above. To learn more, go through the complete documentation [here](https://github.com/azsk/DevOpsKit-docs).

## Steps To Install the package:
1. `Register-PSRepository -Name [PoshTestGallery|PSGallery] -SourceLocation https://www.poshtestgallery.com/api/v2/ -InstallationPolicy Trusted`
<br>
(Set the gallery name to _PSGallery_ for the prod version and _PoshTestGallery_ for dev version/bugbash purpose.)

2. `Install-module AzSKStaging.AAD -Repository PoshTestGallery -Force -AllowClobber -Scope CurrentUser`
<br>Install latest version of the said module

3. `ipmo AzSKStaging.AAD`
<br>Importing the package

## Running the scanner: 
1. `Get-AzSKAADSecurityStatusTenant -TenantId <yourTenantId> -IncludeDetailedResult #Tenant scan`
<br>Tenant scan cmdlet

2. `Get-AzSKAADSecurityStatusUser -TenantId <yourTenantId> -IncludeDetailedResult -mo 10 #User owned objects scan`
<br>User owned objects scan cmdlet