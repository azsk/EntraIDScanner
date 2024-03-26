*** This README file describes how to interpret the different files created when AzSK PS cmdlets are executed ***

## Index
1. [AzSK Root Output Folder](#azsk-root-output-folder)
2. [Sub-Folders](#sub-folders)
3. [Contents of Output Folder](#contents-of-output-folder)
4. [Usage Guidelines](#usage-guidelines)
5. [Field descriptions in SecurityReport.csv](#field-descriptions-in-securityreportcsv)

## AzSK Root Output Folder

Each AzSK cmdlet writes output to a folder whose location is determined as below:

AzSK-Root-Output-Folder = `%LocalAppData%\Microsoft\AzSK.AAD\Logs`

Example: `"C:\Users\<userName>\AppData\Local\Microsoft\AzSK.AAD\Logs"`

## Sub-Folders

Sub-Folder = `Org_<OrganizationName><Timestamp>_<Command Abbreviation>`

Example: `"Org_[yourSubscriptionId]\20170321_183800_GSS"`

Thus, the full path to an output folder for a specific cmdlet might look like:

Example: `"C:\Users\userName\AppData\Local\Microsoft\AzSK.AAD\Logs\Org_72f999bf-86f5-59ez-91ab-2c9ac011db77\20170321_183800_GSS"`

By default, cmdlets open this folder upon completion of the cmdlet (we assume you'd be interested in examining the control evaluation status, etc).

---

## Contents of Output Folder

- `SecurityReport-<timestamp>.csv`: Summary CSV file listing all applicable controls and their evaluation status. Generated only for scan cmdlets like `Get-AzSKAzureServicesSecurityStatus`, `Get-AzSKSubscriptionSecurityStatus`, etc.
- `AttestationReport-<timestamp>.csv`: Summary CSV file listing all applicable controls and their attestation details. Generated only for the cmdlet `Get-AzSKInfo -tenantId <tenantId> -InfoType AttestationInfo`.
- `<Organization_or_Project_Folder>`: Folder corresponding to the project or organization that was evaluated. If multiple projects were scanned, there is one folder for each project.
  - `<resourceType>.LOG`: Detailed/raw output log of controls evaluated for a given resource type within a project.
- `Etc`: Contains some other logs capturing the runtime context of the command.
  - `PowerShellOutput.LOG`: Raw PS console output captured in a file.
  - `EnvironmentDetails.LOG`: Log file containing environment data of the current PowerShell session.
  - `SecurityEvaluationData.json`: Detailed security data for each control that was evaluated. Generated only for SVT cmdlets like `Get-AzSKAADTenantSecurityStatus`, etc.
- `FixControlScripts`: Folder containing scripts to fix failing controls where fix-script is supported. Generated only when the 'GenerateFixScript' switch is passed and one or more failed controls support automated fixing.
  - `README.txt`: Help file describing the 'FixControlScripts' folder.

---

## Usage Guidelines

1. The `SecurityReport.CSV` file provides a gist of the control evaluation results. Investigate those that say 'Verify' or 'Failed'.
2. For 'Failed' or 'Verify' controls, look in the `<resourceType>.LOG` file (search by control-id) to help you understand why the control has failed.
3. For 'Verify' controls, you will also find the `SecurityEvaluationData.JSON` file in the `\Etc` sub-folder handy.
4. To remediate the controls, you can also use the 'Recommendation' field in the control output to quickly get to the PS command to address the issue.
5. Make changes as needed to the subscription/resource configs based on steps 2, 3, and 4.
6. Rerun the cmdlet and verify that the controls you just attempted fixes for are passing now.

---

## Field descriptions in SecurityReport.csv
| Field Name          | Description                                                                                            |
|---------------------|--------------------------------------------------------------------------------------------------------|
| ControlID           | Unique identifier assigned to each security control                                                    |
| Status              | Indicates the current status or outcome of the security control (e.g., Passed, Failed, Not Applicable) |
| FeatureName         | Name of the specific feature or functionality associated with the security control                     |
| ResourceName        | Name of the resource scanned                                                                           |
| ControlSeverity     | Level of severity assigned to the security control based on its importance and potential impact        |
| IsBaselineControl   | Flag indicating whether the control is a baseline control, referring to a high security impact configuration|
| IsControlInGrace    | Flag indicating whether the control is currently in a grace period                                     |
| SupportsAutoFix     | Indicates whether the security control supports automatic remediation                                  |
| Description         | Brief explanation or summary of the security control                                                   |
| Recommendation      | Steps to remediate the security control                                                                |
| ResourceId          | Unique identifier of resource being scanned                                                            | 
| DetailedLogFile     | Location of the detailed log file containing additional information about the security control evaluation process and results|
| DetailedResult      | A more detailed result of the security control evaluation                                              |


[Go back to Top](#index)