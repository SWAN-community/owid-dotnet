
param(
    [string]$ProjectDir = ".",
    [string]$Name,
    [Parameter(Mandatory=$true)]
    [string]$RepoName
)

./dotnet/run-update-dependencies.ps1 -RepoName $RepoName -ProjectDir Owid.sln -Name $Name

exit $LASTEXITCODE
