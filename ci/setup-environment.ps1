param(
    [Parameter(Mandatory=$true)]
    [string]$OrgName,
    [string]$GitHubUser = "Automation51D"
)

./dotnet/add-nuget-source.ps1 `
    -Source "https://nuget.pkg.github.com/$OrgName/index.json" `
    -UserName $GitHubUser `
    -Key $env:GITHUB_TOKEN

exit $LASTEXITCODE
