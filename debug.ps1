Import-Module ".\AzSK.AAD.psd1"

Get-AzSKAADSecurityStatusUser -TenantId "72f988bf-86f1-41af-91ab-2d7cd011db47" -ObjectTypes "Application" -MaxObj 10