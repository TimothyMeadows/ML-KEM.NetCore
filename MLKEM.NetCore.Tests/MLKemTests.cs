using System.Security.Cryptography;
using System.Text;
using System.Numerics;
using MLKEM.NetCore;

namespace MLKEM.NetCore.Tests;

public class MLKemTests
{
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void EncapsulationRoundTrip(MLKemParameterSet set)
    {
        var kem = new MLKem(set);
        Span<byte> d = stackalloc byte[32];
        Span<byte> z = stackalloc byte[32];
        Span<byte> m = stackalloc byte[32];

        for (var i = 0; i < 32; i++)
        {
            d[i] = (byte)i;
            z[i] = (byte)(i + 32);
            m[i] = (byte)(255 - i);
        }

        var keyPair = kem.GenerateKeyPair(d, z);
        using (keyPair.SecretKey)
        {
            var sk = keyPair.SecretKey.Read().AsSpan(0, kem.SecretKeyBytes).ToArray();
            var encapsulation = kem.EncapsulateDeterministic(keyPair.PublicKey, m);
            using (encapsulation.SharedSecret)
            {
                var ss1 = encapsulation.SharedSecret.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                using var ss2Pinned = kem.Decapsulate(sk, encapsulation.CipherText);
                var ss2 = ss2Pinned.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                Assert.Equal(ss1, ss2);
            }
        }
    }

    [Fact]
    public void SecurePinnedApisRoundTrip()
    {
        var kem = new MLKem(MLKemParameterSet.MLKem768);

        var keyPair = kem.GenerateKeyPair();
        using (keyPair.SecretKey)
        {
            var sk = keyPair.SecretKey.Read();
            var encapsulation = kem.Encapsulate(keyPair.PublicKey);
            using (encapsulation.SharedSecret)
            {
                var ss1 = encapsulation.SharedSecret.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                using var pinnedSs2 = kem.Decapsulate(sk.AsSpan(0, kem.SecretKeyBytes), encapsulation.CipherText);
                var ss2 = pinnedSs2.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                Assert.Equal(ss1, ss2);
            }
        }
    }

    [Fact]
    public void AliceAndBobDeriveSameSharedSecret()
    {
        var kem = new MLKem(MLKemParameterSet.MLKem768);

        var aliceKeyPair = kem.GenerateKeyPair();
        using (aliceKeyPair.SecretKey)
        {
            var bobEncapsulation = kem.Encapsulate(aliceKeyPair.PublicKey);
            using (bobEncapsulation.SharedSecret)
            {
                var aliceSecretKey = aliceKeyPair.SecretKey.Read().AsSpan(0, kem.SecretKeyBytes);
                using var aliceSharedSecretPinned = kem.Decapsulate(aliceSecretKey, bobEncapsulation.CipherText);

                var bobSharedSecret = bobEncapsulation.SharedSecret.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                var aliceSharedSecret = aliceSharedSecretPinned.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();

                Assert.True(CryptographicOperations.FixedTimeEquals(bobSharedSecret, aliceSharedSecret));
            }
        }
    }

    [Fact]
    public void DecapsulationRejectsTamperedCiphertext()
    {
        var kem = new MLKem(MLKemParameterSet.MLKem512);
        var keyPair = kem.GenerateKeyPair();
        using (keyPair.SecretKey)
        {
            var sk = keyPair.SecretKey.Read().AsSpan(0, kem.SecretKeyBytes).ToArray();
            var encapsulation = kem.Encapsulate(keyPair.PublicKey);
            using (encapsulation.SharedSecret)
            {
                encapsulation.CipherText[0] ^= 0x01;

                using var tampered = kem.Decapsulate(sk, encapsulation.CipherText);
                var ss1 = encapsulation.SharedSecret.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                var ss2 = tampered.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();

                Assert.False(CryptographicOperations.FixedTimeEquals(ss1, ss2));
            }
        }
    }

    [Fact]
    public void Rfc9936StyleKnownVector_MLKEM512()
    {
        var kem = new MLKem(MLKemParameterSet.MLKem512);
        var d = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var z = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
        var m = Enumerable.Range(64, 32).Select(i => (byte)i).ToArray();

        var keyPair = kem.GenerateKeyPair(d, z);
        using (keyPair.SecretKey)
        {
            var sk = keyPair.SecretKey.Read().AsSpan(0, kem.SecretKeyBytes).ToArray();
            var encapsulation = kem.EncapsulateDeterministic(keyPair.PublicKey, m);
            using (encapsulation.SharedSecret)
            {
                var ss1 = encapsulation.SharedSecret.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
                using var ss2Pinned = kem.Decapsulate(sk, encapsulation.CipherText);
                var ss2 = ss2Pinned.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();

                Assert.Equal("AEFB3F3D06D04774C8F6510981BEE9F325BDD3BDCD03E71CFC07B02AD2A4EB1C", ToHex(Sha256(keyPair.PublicKey)));
                Assert.Equal("F131A046C5AF2AAE65152923A5A4A4681D7892382143350176EF825D843CCB0A", ToHex(Sha256(sk)));
                Assert.Equal("B81D92411CA9CA3308F7EB7512F31FDEA645F3F8A496C561A673C2397D2F2B98", ToHex(Sha256(encapsulation.CipherText)));
                Assert.Equal("0C9DD2E29023B2DAB3F6912F09E2195AAE805F59B8B6DCD8ED79BD26F312D61F", ToHex(ss1));
                Assert.Equal(ss1, ss2);
            }
        }
    }

    private static byte[] Sha256(byte[] input) => SHA256.HashData(input);

    private static string ToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (var b in data)
        {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }
}


public class MLKemSimdTests
{
    [Fact]
    public void ScalarAndVectorizedModesProduceIdenticalOutputs()
    {
        var kem = new MLKem(MLKemParameterSet.MLKem768);
        var d = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();
        var z = Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray();
        var m = Enumerable.Range(0, 32).Select(i => (byte)(i * 3)).ToArray();

        var originalMode = MLKem.SimdExecutionMode;
        try
        {
            MLKem.SimdExecutionMode = MLKem.SimdMode.ForceDisabled;
            var scalarKeys = kem.GenerateKeyPair(d, z);
            using var scalarSecretPinned = scalarKeys.SecretKey;
            var scalarSecret = scalarSecretPinned.Read().AsSpan(0, kem.SecretKeyBytes).ToArray();
            var scalarEncapsulation = kem.EncapsulateDeterministic(scalarKeys.PublicKey, m);
            using var scalarSharedPinned = scalarEncapsulation.SharedSecret;
            var scalarSharedSecret = scalarSharedPinned.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
            using var scalarShared = kem.Decapsulate(scalarSecret, scalarEncapsulation.CipherText);
            var scalarSharedDecapsulated = scalarShared.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();

            MLKem.SimdExecutionMode = MLKem.SimdMode.ForceEnabled;
            var simdKeys = kem.GenerateKeyPair(d, z);
            using var simdSecretPinned = simdKeys.SecretKey;
            var simdSecret = simdSecretPinned.Read().AsSpan(0, kem.SecretKeyBytes).ToArray();
            var simdEncapsulation = kem.EncapsulateDeterministic(simdKeys.PublicKey, m);
            using var simdSharedPinned = simdEncapsulation.SharedSecret;
            var simdSharedSecret = simdSharedPinned.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();
            using var simdShared = kem.Decapsulate(simdSecret, simdEncapsulation.CipherText);
            var simdSharedDecapsulated = simdShared.Read().AsSpan(0, kem.SharedSecretBytes).ToArray();

            Assert.Equal(scalarKeys.PublicKey, simdKeys.PublicKey);
            Assert.Equal(scalarSecret, simdSecret);
            Assert.Equal(scalarEncapsulation.CipherText, simdEncapsulation.CipherText);
            Assert.Equal(scalarSharedSecret, simdSharedSecret);
            Assert.Equal(scalarSharedSecret, scalarSharedDecapsulated);
            Assert.Equal(simdSharedSecret, simdSharedDecapsulated);
            Assert.Equal(scalarSharedDecapsulated, simdSharedDecapsulated);
        }
        finally
        {
            MLKem.SimdExecutionMode = originalMode;
        }
    }

    [Fact]
    public void ReportsPolyArithmeticSpeedupEstimate()
    {
        var originalMode = MLKem.SimdExecutionMode;
        try
        {
            MLKem.SimdExecutionMode = MLKem.SimdMode.Auto;
            var speedup = MLKem.EstimatePolyArithmeticSpeedup(20_000);
            Console.WriteLine($"Estimated SIMD speedup (poly add/sub): {speedup:F3}x");

            Assert.True(double.IsFinite(speedup));
            Assert.True(speedup > 0);
            if (Vector.IsHardwareAccelerated)
            {
                Assert.True(speedup > 0.2);
            }
        }
        finally
        {
            MLKem.SimdExecutionMode = originalMode;
        }
    }
}
