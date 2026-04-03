param(
    [string]$ProjectDir = ".",
    [Parameter(Mandatory=$true)]
    [string]$RepoName,
    [string]$Name = "Release_x64",
    [string]$Configuration = "Release",
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [Parameter(Mandatory=$true)]
    [Hashtable]$Keys

)

. "./$RepoName/ci/setup-environment.ps1" -OrgName $OrgName

Write-Output "Building Nuget Package for FiftyOne.PropertyKeyedEngine"  
./dotnet/build-package-nuget.ps1 `
    -RepoName $RepoName `
    -Configuration "Release" `
    -Version $Version `
    -SolutionName "Owid.sln" `
    -SearchPattern "^Project\(.*csproj" `
    -CodeSigningKeyVaultUrl $Keys.CodeSigningKeyVaultUrl `
    -CodeSigningKeyVaultClientId $Keys.CodeSigningKeyVaultClientId `
    -CodeSigningKeyVaultTenantId $Keys.CodeSigningKeyVaultTenantId `
    -CodeSigningKeyVaultClientSecret $Keys.CodeSigningKeyVaultClientSecret `
    -CodeSigningKeyVaultCertificateName $Keys.CodeSigningKeyVaultCertificateName

exit $LASTEXITCODE
