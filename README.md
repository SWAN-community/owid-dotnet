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

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain has no
separate encoded maximum, so the protocol alone is not an application input
limit for the complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it sizes or copies the payload. A large declaration without
the corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The in-memory APIs remain subject to .NET array, stream, address-space and
available-memory limits. Applications accepting untrusted OWIDs must choose
limits suitable for their use case and enforce them before buffering the
binary form or decoding Base64. An implementation capacity failure or an
application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope, and
allow for the domain and the other OWID fields as well as the payload. After
parsing, `owid.PayloadLength` reports the actual payload size for downstream
policy without copying the payload to answer the question, whereas
`owid.Payload` hands out a copy every time it is read. The parser cannot
choose either limit on behalf of the application.

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

// Create and sign a new OWID over a payload. Creating and signing are the
// same step, because an OWID cannot exist in an unsigned state.
var owid = creator.Create("example payload");

// Serialize to a Base64 string for transmission or storage.
var base64 = owid.AsBase64();
```

### Verify an OWID

```csharp
using System.Security.Cryptography;
using Owid.Client;
using Owid.Client.Model;

// Read the OWID from its Base64 form. Data arriving from outside is expected
// to be malformed sometimes, so this reports why rather than throwing.
if (Owid.Client.Model.Owid.TryParse(
        base64, out var owid, out var status) == false)
{
    // owid is null and status says which of the expected problems it was.
    return;
}

// Ask whether the signature is genuine, keeping "does not match" apart from
// "could not check".
var signature = owid!.SignatureStatus(publicPem);
if (signature == OwidSignatureStatus.SignatureValid)
{
    // Trust the identifier.
}
else if (signature == OwidSignatureStatus.SignatureInvalid)
{
    // The only answer that means the identifier should be distrusted.
}
else
{
    // The question could not be answered, so nothing has been proved either
    // way. Rejecting here would turn a key outage into a wave of forgeries.
}

// The boolean surfaces remain for callers that only need yes or no.
using (var crypto = ECDsa.Create())
{
    crypto.ImportFromPem(publicPem);
    var valid = await owid!.VerifyAsync(crypto);
}

// Or verify by fetching the public key from the creator's domain.
var validFromDomain = await owid!.VerifyAsync();
```

### Read an OWID, and what a failure means

Three surfaces read an OWID, and none of them throws for bad data, because an
OWID is read from whatever a caller was given, which on a public endpoint
means anything at all.

```csharp
Owid.Client.Model.Owid.TryParse(base64, out var a, out var first);
Owid.Client.Model.Owid.TryParse(bytes, out var b, out var second);
Owid.Client.Model.Owid.TryRead(stream, out var c, out var third);
```

`TryParse` reads a whole buffer, where the envelope is all there is, so the
declared payload must leave exactly the signature and nothing else, and any
trailing byte is a `ByteCountMismatch`.

`TryRead` reads one envelope from a stream that may carry more after it, which
is what a tree of identifiers written one after another needs. What follows is
not the parse's to judge, so it needs the declared payload and the signature to
be present and says nothing about the rest. Because it can say nothing about a
disagreement, a stream stopping short is an `UnexpectedEnd`, which is what a
caller reading from a source still arriving needs to know. It reads forward
only, never asks the stream for its length, and collects the payload in fixed
pieces, so a declared count cannot decide an allocation before the bytes that
justify it have arrived.

`OwidParseStatus` says why a read failed.

| Status | Meaning |
|--------|---------|
| `Parsed` | Structurally valid. Says nothing about the signature. |
| `MissingInput` | Nothing was supplied, or a stream had nothing left. |
| `InvalidInputType` | The input arrived in a form the surface cannot read. |
| `InvalidBase64` | The string is not valid Base64, so there are no bytes. |
| `UnsupportedVersion` | The first byte names a version this library does not know. |
| `UnexpectedEnd` | The data stopped in the middle of a field. |
| `InvalidDomainEncoding` | The domain is not terminated, or is too long. |
| `ByteCountMismatch` | The declared payload count disagrees with the bytes present. |
| `ImplementationCapacityExceeded` | Valid, but larger than this runtime can hold, or dated past the end of 9999 where `DateTime` stops. |
| `MalformedEnvelope` | Malformed in a way none of the above describes. |
| `AbsentNode` | The version 0 marker, which stands for an absent node. |

Version 0 is the marker written into a stream to stand for an absent node in a
tree. It carries no domain, date, payload or signature, so no value is handed
back and it can never verify. `TryRead` takes its one byte and reports
`AbsentNode`, so a caller walking a run of frames can tell a gap from rubbish
and reach whatever follows the gap.

```csharp
while (Owid.Client.Model.Owid.TryRead(stream, out var next, out var s)
    || s == OwidParseStatus.AbsentNode)
{
    // next is the envelope, or null where the tree had no node here.
}
```

`OwidSignatureStatus` keeps "does not match" apart from "could not check". A
key that cannot be fetched, cannot be decoded, or is of the wrong type leaves
the signature unjudged, and treating that as invalid would report an outage as
an attack. On 30 August 2026 the key end points served PEM that a strict parser
rejects, and every offline check against them failed while the keys and the
identifiers were all fine.

### An OWID cannot exist unsigned

There is no public constructor. An instance reaches a caller from a successful
read or from a `Creator` that signs it into existence, never half made, because
an unsigned OWID is indistinguishable from a signed one to the code downstream
of it and the difference only surfaces later, somewhere that is not looking.
`Version`, `Domain`, `Date`, `Payload` and `Signature` are read only, and
`Payload` and `Signature` are handed out as copies so writing into what a
caller was given cannot alter an OWID whose signature covers the original
bytes.

### Chained sign and verify with others

An OWID can be signed over other OWIDs. Verification then requires the same
other OWIDs to be supplied in the same order.

```csharp
var first = creator.Create("first");
var second = creator.Create("second");

// Create and sign a new OWID over the two others.
var chained = creator.Create(payload, first, second);

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
`/owid/api/v2/public-key`, `/owid/api/v3/public-key` and the equivalent
`creator` paths. Use the v3 paths for new integrations; v1 and v2 remain for
backwards compatibility.

### Historical keys (rotating signing keys)

By default the public-key endpoint returns the single key from
`OwidConfiguration`. A creator that rotates its signing key can serve the key
that was in force at a given date by registering an `IPublicKeyStore` (types in
`Owid.Client.Model`). Each key carries the moment its period starts, and it
holds until the next key starts:

```csharp
builder.Services.AddSingleton<IPublicKeyStore>(new DatedKeyStore(new[]
{
    new DatedPublicKey { StartsAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = previousPem },
    new DatedPublicKey { StartsAt = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = currentPem },
}));
```

Callers pass the OWID's own date as `?date=<minutes>`, where `date` is the
number of minutes since `2020-01-01` UTC (the OWID Date encoding):

`GET /owid/api/v1/public-key?date=<minutes>`

The endpoint returns the key with the latest `StartsAt` on or before `date`,
the key in force now when `date` is omitted, and `404` when `date` precedes
the oldest known key. Implement `IPublicKeyStore` to plug in any key source.

`StartsAt` is the schedule position and not the moment the key material was
generated. The two only agree whilst keys are generated one period at a time,
and a creator that writes several future periods in one run breaks the
agreement, so selecting on the moment of generation then returns a key whose
period has not started and every genuine identifier of that period reads as
forged. Give this store the start of each period. For the same reason, a
store with no date to work from must answer with the key in force now rather
than the last entry of a schedule written ahead of time.

### Requiring authentication (optional)

The OWID specification leaves authentication to the implementor: a creator
MAY require a credential on the public-key and creator endpoints, for
example to tie key access to a subscription. Register an `IOwidAuthorizer`
to enforce your own rule; without one the endpoints stay open. The check is
async so it can call a database or another service.

```csharp
public class RequireApiKey : IOwidAuthorizer
{
    public Task<ActionResult?> AuthorizeAsync(HttpRequest request)
    {
        // Accept the credential from a header, the query string, or a form
        // field, and name all three in the 401, as the OWID spec recommends.
        var present =
            request.Headers.ContainsKey("X-Api-Key") ||
            request.Query.ContainsKey("apiKey") ||
            (request.HasFormContentType && request.Form.ContainsKey("apiKey"));
        ActionResult? denied = present
            ? null // allowed
            : new UnauthorizedObjectResult(
                "An API key is required. Supply it as the X-Api-Key header, " +
                "an apiKey query parameter, or an apiKey form field.");
        return Task.FromResult(denied);
    }
}

builder.Services.AddSingleton<IOwidAuthorizer>(new RequireApiKey());
```

The 51Degrees cloud, for example, requires a resource key or license key on
these endpoints and meters each call.

## Testing

```
dotnet test
```

The tests cover creation, signing, verification, serialization, chaining and
the controllers. The suite also includes externally signed fixtures which
prove that the wire format and signatures are portable.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
