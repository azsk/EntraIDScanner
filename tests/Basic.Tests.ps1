Describe 'Basic Tests' {
    BeforeAll {
        function CheckForErrorsInCsv {
            param (
                [string]
                [Parameter(Position = 0, Mandatory = $true, HelpMessage="CsvFile Path")]
                [ValidateNotNullOrEmpty()]
                $ResultPath,

                [int]
                [Parameter(Position = 0, Mandatory = $true, HelpMessage="CsvFile Path")]
                $MaxObjectsScanned
            )
            
                $CsvFile = Get-ChildItem -Path $ResultPath -Recurse -Filter "*.csv";
                $CsvContent = Import-Csv -Path $CsvFile;

                # Check if any controls errored out
                $erroredControls = @($CsvContent | Where-Object { $_.Status -eq "Error" });
                $erroredControls | Should -BeNullOrEmpty;

                # Check the count of scanned objects
                $scannedApplications = @($CsvContent | Where-Object {$_.FeatureName -eq "AppRegistration" } | ForEach-Object { $_.ResourceName } | Get-Unique)
                $scannedApplications.Count | Should -BeExactly $MaxObjectsScanned;
                $scannedServicePrincipals = @($CsvContent | Where-Object {$_.FeatureName -eq "EnterpriseApplication" } | ForEach-Object { $_.ResourceName } | Get-Unique)
                $scannedServicePrincipals.Count | Should -BeExactly $MaxObjectsScanned;
                
                # Check Detialed Results are included
                $CsvFile | ForEach-Object {
                    $CsvContent = Import-Csv -Path $_.FullName;
                    $CsvContent | Where-Object { $_.DetailedResult -ne "" } | Should -Not -BeNullOrEmpty;
                }
        }

        Import-Module './AzSK.EntraID.psd1'
    }

    BeforeEach {
        $TestCtx = @{
            resultPath = ""
            tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"
        };
    }

    AfterEach {
        [System.IO.Directory]::Delete($TestCtx.resultPath, $true) | Out-Null;
    }


    It 'Should run tenant scan for microsoft tenant on all types' {
        $maxObj = 3;
        $TestCtx.resultPath = (Get-AzSKEntraIDSecurityStatusTenant -TenantId $TestCtx.tenantId -MaxObj $maxObj -IncludeDetailedResult);
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "AppRegistration.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "Device.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "EnterpriseApplication.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "Group.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "Tenant.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "User.LOG")) | Should -Be $true; 
        CheckForErrorsInCsv -ResultPath $TestCtx.resultPath -MaxObjectsScanned $maxObj;
        
    }

    It 'Should run a user scan for microsoft tenant on all types' {
        $maxObj = 3;
        $TestCtx.resultPath = (Get-AzSKEntraIDSecurityStatusUser -TenantId $TestCtx.tenantId -MaxObj $maxObj -IncludeDetailedResult);
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "AppRegistration.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "Device.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "EnterpriseApplication.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "Group.LOG")) | Should -Be $true;
        Test-Path $([System.IO.Path]::Combine($TestCtx.resultPath, "User.LOG")) | Should -Be $true; 
        CheckForErrorsInCsv -ResultPath $TestCtx.resultPath -MaxObjectsScanned 1;
    }
}