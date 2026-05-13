
param(
    [Parameter(Mandatory=$true)]
    [string]$RepoName,
    [Parameter(Mandatory=$true)]
    [string]$OrgName,
    [string]$GitHubUser = "Automation51D",
    [string]$Version,
    [string]$ProjectDir = ".",
    [string]$Name = "Release_x64"
)

Write-Output "Publishing to Github"

./dotnet/publish-package-github.ps1 `
    -RepoName $RepoName `
    -OrgName $OrgName `
    -ProjectDir $ProjectDir `
    -Name $Name `
    -ApiKey $env:GITHUB_TOKEN

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

exit $LASTEXITCODE
