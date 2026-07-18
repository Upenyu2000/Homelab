param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\evidence\identity\entra-users.csv"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    throw "Microsoft.Graph.Users is required. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
}

Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All"

$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,Department,UserType,CreatedDateTime,SignInActivity
$report = $users | Select-Object `
    @{Name="user_id";Expression={$_.Id}},
    @{Name="display_name";Expression={$_.DisplayName}},
    @{Name="user_principal_name";Expression={$_.UserPrincipalName}},
    @{Name="department";Expression={$_.Department}},
    @{Name="account_enabled";Expression={$_.AccountEnabled}},
    @{Name="user_type";Expression={$_.UserType}},
    @{Name="created";Expression={$_.CreatedDateTime}},
    @{Name="last_sign_in";Expression={$_.SignInActivity.LastSignInDateTime}}

$directory = Split-Path -Parent $OutputPath
if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($report.Count) identities to $OutputPath"
