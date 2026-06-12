# ![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID)

## Overview

Open Web Id (OWID) is a small cryptographically signed identifier. Each OWID
records the domain of its creator, the date and time of creation to the
minute, an arbitrary payload, and an ECDSA P-256 signature which allows anyone
to verify that the data has not been altered since it was signed. OWIDs can
also be signed over other OWIDs to form verifiable chains. Read the
[OWID](https://github.com/SWAN-community/owid) project to learn more about the
concepts behind this implementation.

## Scope of this implementation

This repository contains a full .NET client for OWID. It can create, sign and
verify OWIDs, and serialize them to and from byte arrays and Base64 strings.
It also provides an ASP.NET Core controller which serves the public key and
creator endpoints that other parties use when verifying OWIDs from your
domain.

The solution contains three projects.

| Project | Purpose |
|---|---|
| `Owid.Client` | Core model, creation, signing, verification and serialization. |
| `Owid.Client.Controllers` | ASP.NET Core controller for the public key and creator endpoints. |
| `Owid.Client.Test` | MSTest unit tests. |

## Installation

```
dotnet add package Owid.Client
dotnet add package Owid.Client.Controllers
```

## Usage

### Configure a creator and sign a payload

```csharp
using Owid.Client;
using Owid.Client.Model.Configuration;

var configuration = new OwidConfiguration
{
    Domain = "example.com",
    PrivateKey = privatePem, // PEM encoded ECDSA P-256 private key
    PublicKey = publicPem    // PEM encoded ECDSA P-256 public key
};
var creator = new Creator(configuration);

// Sign a payload to produce a new OWID.
var owid = creator.Sign("example payload");

// Serialize to a Base64 string for transmission or storage.
var base64 = owid.AsBase64();
```

### Verify an OWID

```csharp
using System.Security.Cryptography;
using Owid.Client;

// Parse the OWID from its Base64 form.
var owid = new Owid.Client.Model.Owid(base64);

// Verify with a known public key.
using (var crypto = ECDsa.Create())
{
    crypto.ImportFromPem(publicPem);
    var valid = await owid.VerifyAsync(crypto);
}

// Or verify by fetching the public key from the creator's domain.
var validFromDomain = await owid.VerifyAsync();
```

### Chained sign and verify with others

An OWID can be signed over other OWIDs. Verification then requires the same
other OWIDs to be supplied in the same order.

```csharp
var first = creator.Sign("first");
var second = creator.Sign("second");

// Sign a new OWID over the two others.
var chained = creator.Sign(
    new Owid.Client.Model.Owid { Payload = payload },
    first,
    second);

// Verification succeeds only with the same others.
using (var crypto = ECDsa.Create())
{
    crypto.ImportFromPem(publicPem);
    var valid = await chained.VerifyAsync(crypto, first, second);
}
```

### Serve the public key and creator endpoints

Add a reference to `Owid.Client.Controllers` and register the configuration so
that `OwidController` is available to the ASP.NET Core pipeline.

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(new OwidConfiguration
{
    Domain = "example.com",
    PrivateKey = privatePem,
    PublicKey = publicPem
});
builder.Services
    .AddControllers()
    .AddApplicationPart(typeof(OwidController).Assembly);

var app = builder.Build();
app.MapControllers();
app.Run();
```

The controller then responds to `/owid/api/v1/public-key`,
`/owid/api/v2/public-key` and the equivalent `creator` paths.

## Testing

```
dotnet test
```

The tests cover creation, signing, verification, serialization, chaining and
the controllers. They also verify fixtures signed by the Rust and Go
implementations to prove cross-language compatibility.

## Related repositories

- [owid](https://github.com/SWAN-community/owid) for the specification and concepts
- [owid-go](https://github.com/SWAN-community/owid-go) for the Go implementation
- [owid-js](https://github.com/SWAN-community/owid-js) for the JavaScript implementation
- [owid-rust](https://github.com/SWAN-community/owid-rust) for the Rust implementation

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
