# ML-KEM.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![nuget](https://img.shields.io/nuget/v/ML-KEM.NetCore.svg)](https://www.nuget.org/packages/ML-KEM.NetCore/)

`ML-KEM.NetCore` is a pure managed .NET implementation of the NIST-standardized ML-KEM (Kyber) post-quantum key encapsulation mechanism.

The library targets **.NET 8** and uses [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) for secret key and shared secret material to improve lifecycle control.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
  - [Pinned-memory encapsulation flow](#pinned-memory-encapsulation-flow)
- [API reference](#api-reference)
  - [`MLKemParameterSet`](#mlkemparameterset)
  - [`MLKem`](#mlkem)
  - [Result types](#result-types)
- [Parameter sizes](#parameter-sizes)
- [Best practices](#best-practices)
- [Validation and testing](#validation-and-testing)
- [Development](#development)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building and running tests.
- Project target framework: **`net8.0`**.

---

## Installation

### From source

Clone the repository and reference the `MLKEM.NetCore` project from your solution.

### NuGet (when published)

```bash
dotnet add package ML-KEM.NetCore
```

---

## Quick start

### Pinned-memory encapsulation flow

```csharp
using MLKEM.NetCore;

var kem = new MLKem(MLKemParameterSet.MLKem768);
var keyPair = kem.GenerateKeyPair();

using (keyPair.SecretKey)
{
    var encapsulation = kem.Encapsulate(keyPair.PublicKey);
    using (encapsulation.SharedSecret)
    {
        var secretKey = keyPair.SecretKey.Read().AsSpan(0, kem.SecretKeyBytes);
        using var sharedSecretBob = kem.Decapsulate(secretKey, encapsulation.CipherText);

        // Compare or use shared secrets, then dispose to scrub.
    }
}
```

---

## API reference

## `MLKemParameterSet`

```csharp
enum MLKemParameterSet
{
    MLKem512,
    MLKem768,
    MLKem1024
}
```

Selects the NIST parameter set used by an `MLKem` instance.

---

## `MLKem`

### Constructor

```csharp
MLKem(MLKemParameterSet parameterSet)
```

### Size properties

```csharp
int PublicKeyBytes { get; }
int SecretKeyBytes { get; }
int CipherTextBytes { get; }
int SharedSecretBytes { get; } // always 32
```

### Key generation

```csharp
SecureKeyPair GenerateKeyPair()
SecureKeyPair GenerateKeyPair(ReadOnlySpan<byte> d, ReadOnlySpan<byte> z)
```

- Deterministic generation requires `d` and `z` to be exactly 32 bytes each.

### Encapsulation

```csharp
EncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
EncapsulationResult EncapsulateDeterministic(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> m)
```

- `EncapsulateDeterministic(...)` requires `m` to be exactly 32 bytes.

### Decapsulation

```csharp
PinnedMemory<byte> Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> cipherText)
```

- Input lengths are validated and must match the selected parameter set sizes.

---

## Result types

```csharp
sealed class SecureKeyPair
{
    byte[] PublicKey { get; }
    PinnedMemory<byte> SecretKey { get; }
}

sealed class EncapsulationResult
{
    byte[] CipherText { get; }
    PinnedMemory<byte> SharedSecret { get; }
}
```

---

## Parameter sizes

Per instantiated `MLKem` object:

- `MLKem512`
  - Public key: 800 bytes
  - Secret key: 1632 bytes
  - Ciphertext: 768 bytes
  - Shared secret: 32 bytes
- `MLKem768`
  - Public key: 1184 bytes
  - Secret key: 2400 bytes
  - Ciphertext: 1088 bytes
  - Shared secret: 32 bytes
- `MLKem1024`
  - Public key: 1568 bytes
  - Secret key: 3168 bytes
  - Ciphertext: 1568 bytes
  - Shared secret: 32 bytes

---

## Best practices

1. **Use secure APIs for secret-bearing values**
   - Use `GenerateKeyPair`, `Encapsulate`, and `Decapsulate` to keep key material in `PinnedMemory<byte>`.
   - Dispose `PinnedMemory<byte>` instances promptly.

2. **Treat parameter sets as protocol constants**
   - Do not mix parameter sets between peers.
   - Validate all serialized key/ciphertext lengths before use.

3. **Prefer deterministic APIs only for tests/vectors**
   - In production, use randomized `GenerateKeyPair()` and `Encapsulate()`.

4. **Keep secret data lifetime short**
   - Zero and dispose sensitive buffers as soon as possible.

---

## Validation and testing

The test suite includes:

- Deterministic known-answer-style vector checks
- Encapsulation/decapsulation round-trip checks across parameter sets
- Ciphertext tamper rejection behavior
- Secure API behavior and memory handling coverage

Run all tests:

```bash
dotnet test MLKEM.sln
```

---

## Development

### Build

```bash
dotnet build MLKEM.sln
```

### Test

```bash
dotnet test MLKEM.sln
```

---

## Security notes

This implementation follows ML-KEM constructions in **RFC 9936**, including a rejection-sampling path that continues SHAKE output generation until enough coefficients are produced.

Current hardening in this repository:

- Decapsulation uses constant-time ciphertext validation with fallback to `z` on invalid ciphertext.
- Sensitive intermediates in decapsulation are explicitly zeroed before returning.
- All secret key and shared secret APIs expose `PinnedMemory<byte>` for deterministic cleanup of secret-bearing values.
- Public keys and ciphertext remain `byte[]` for interoperability, while key material is pinned.

---

## License

MIT License. See [LICENSE](LICENSE).
