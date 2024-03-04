# Import the data from AzSK.EntraID.psd1 file
$requiredModulesData = Import-PowerShellDataFile -Path "AzSK.EntraID.psd1"

# Extract the required modules and their versions
$requiredModules = $requiredModulesData.RequiredModules

# Iterate through the list of modules and their required versions
foreach ($module in $requiredModules) {
    Write-Output "Installing $($module.ModuleName) version $($module.RequiredVersion)"
    Install-Module -Name $module.ModuleName -RequiredVersion $module.RequiredVersion -Force -Scope CurrentUser -AllowClobber
}

