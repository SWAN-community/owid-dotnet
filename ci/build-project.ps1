param(
    [Parameter(Mandatory=$true)]
    [string]$RepoName,
    [string]$ProjectDir = ".",
    [string]$Name = "Release_x64",
    [string]$Configuration = "Release",
    [string]$Arch = "x64"
)

./dotnet/build-project-core.ps1 -RepoName $RepoName -ProjectDir "Owid.sln" -Name $Name -Configuration $Configuration -Arch $Arch

exit $LASTEXITCODE