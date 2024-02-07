Import-Module ".\AzSK.EntraID.psd1"

Get-AzSKEntraIDSecurityStatusUser -TenantId "72f988bf-86f1-41af-91ab-2d7cd011db47" -ObjectTypes "EnterpriseApplication"  -IncludeDetailedResult