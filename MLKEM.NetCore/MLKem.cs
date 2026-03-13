using System.Security.Cryptography;
using System.Numerics;
using PinnedMemory;

namespace MLKEM.NetCore;

public enum MLKemParameterSet
{
    MLKem512,
    MLKem768,
    MLKem1024
}

public sealed class SecureKeyPair
{
    public SecureKeyPair(byte[] publicKey, PinnedMemory<byte> secretKey)
    {
        PublicKey = publicKey;
        SecretKey = secretKey;
    }

    public byte[] PublicKey { get; }
    public PinnedMemory<byte> SecretKey { get; }
}

public sealed class EncapsulationResult
{
    public EncapsulationResult(byte[] cipherText, PinnedMemory<byte> sharedSecret)
    {
        CipherText = cipherText;
        SharedSecret = sharedSecret;
    }

    public byte[] CipherText { get; }
    public PinnedMemory<byte> SharedSecret { get; }
}

public sealed class MLKem
{
    private const int N = 256;
    private const int Q = 3329;

    internal enum SimdMode
    {
        Auto,
        ForceEnabled,
        ForceDisabled
    }

    internal static SimdMode SimdExecutionMode { get; set; } = SimdMode.Auto;

    private readonly Parameters _p;

    public MLKem(MLKemParameterSet parameterSet)
    {
        _p = parameterSet switch
        {
            MLKemParameterSet.MLKem512 => new Parameters(2, 3, 2, 10, 4),
            MLKemParameterSet.MLKem768 => new Parameters(3, 2, 2, 10, 4),
            MLKemParameterSet.MLKem1024 => new Parameters(4, 2, 2, 11, 5),
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet))
        };
    }

    public int PublicKeyBytes => (_p.K * 384) + 32;
    public int SecretKeyBytes => (_p.K * 384) + PublicKeyBytes + 64;
    public int CipherTextBytes => (_p.K * 32 * _p.Du) + (32 * _p.Dv);
    public int SharedSecretBytes => 32;

    public SecureKeyPair GenerateKeyPair()
    {
        Span<byte> d = stackalloc byte[32];
        Span<byte> z = stackalloc byte[32];
        RandomNumberGenerator.Fill(d);
        RandomNumberGenerator.Fill(z);
        return GenerateKeyPair(d, z);
    }

    public SecureKeyPair GenerateKeyPair(ReadOnlySpan<byte> d, ReadOnlySpan<byte> z)
    {
        if (d.Length != 32 || z.Length != 32)
        {
            throw new ArgumentException("d and z must be 32 bytes each.");
        }

        var kpkeKeyPair = KpkeKeyGen(d);
        var ek = kpkeKeyPair.PublicKey;
        var dkPke = kpkeKeyPair.SecretKey;
        var hEk = Sha3_256(ek);

        var dk = new byte[SecretKeyBytes];
        Buffer.BlockCopy(dkPke, 0, dk, 0, dkPke.Length);
        Buffer.BlockCopy(ek, 0, dk, dkPke.Length, ek.Length);
        Buffer.BlockCopy(hEk, 0, dk, dkPke.Length + ek.Length, 32);
        z.CopyTo(dk.AsSpan(dkPke.Length + ek.Length + 32));

        var pinnedSecretKey = new PinnedMemory<byte>(dk, zero: false, locked: true);
        CryptographicOperations.ZeroMemory(dk);
        return new SecureKeyPair(ek, pinnedSecretKey);
    }

    public EncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        Span<byte> m = stackalloc byte[32];
        RandomNumberGenerator.Fill(m);
        return EncapsulateDeterministic(publicKey, m);
    }

    public EncapsulationResult EncapsulateDeterministic(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> m)
    {
        if (publicKey.Length != PublicKeyBytes)
        {
            throw new ArgumentException($"publicKey must be {PublicKeyBytes} bytes.");
        }

        if (m.Length != 32)
        {
            throw new ArgumentException("m must be 32 bytes.");
        }

        var hEk = Sha3_256(publicKey);
        Span<byte> gIn = stackalloc byte[64];
        m.CopyTo(gIn);
        hEk.CopyTo(gIn[32..]);
        var gOut = Sha3_512(gIn);
        var kBar = gOut.AsSpan(0, 32).ToArray();
        var r = gOut.AsSpan(32, 32).ToArray();

        var c = KpkeEncrypt(publicKey, m, r);
        var hC = Sha3_256(c);

        Span<byte> kdfIn = stackalloc byte[64];
        kBar.CopyTo(kdfIn);
        hC.CopyTo(kdfIn[32..]);
        var ss = Shake256(kdfIn, 32);
        var pinnedSharedSecret = new PinnedMemory<byte>(ss, zero: false, locked: true);
        CryptographicOperations.ZeroMemory(ss);

        return new EncapsulationResult(c, pinnedSharedSecret);
    }

    public PinnedMemory<byte> Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> cipherText)
    {
        if (secretKey.Length != SecretKeyBytes)
        {
            throw new ArgumentException($"secretKey must be {SecretKeyBytes} bytes.");
        }

        if (cipherText.Length != CipherTextBytes)
        {
            throw new ArgumentException($"cipherText must be {CipherTextBytes} bytes.");
        }

        var dkPkeLen = _p.K * 384;
        var ekLen = PublicKeyBytes;

        var dkPke = secretKey[..dkPkeLen].ToArray();
        var ek = secretKey.Slice(dkPkeLen, ekLen).ToArray();
        var hEk = secretKey.Slice(dkPkeLen + ekLen, 32);
        var z = secretKey[(dkPkeLen + ekLen + 32)..].ToArray();

        var mPrime = KpkeDecrypt(dkPke, cipherText);

        Span<byte> gIn = stackalloc byte[64];
        mPrime.CopyTo(gIn);
        hEk.CopyTo(gIn[32..]);
        var gOut = Sha3_512(gIn);
        var kPrime = gOut.AsSpan(0, 32).ToArray();
        var rPrime = gOut.AsSpan(32, 32).ToArray();

        var cPrime = KpkeEncrypt(ek, mPrime, rPrime);
        var isValid = CryptographicOperations.FixedTimeEquals(cPrime, cipherText);

        var hC = Sha3_256(cipherText);
        Span<byte> kdfIn = stackalloc byte[64];
        (isValid ? kPrime : z).CopyTo(kdfIn);
        hC.CopyTo(kdfIn[32..]);
        var sharedSecret = Shake256(kdfIn, 32);

        CryptographicOperations.ZeroMemory(dkPke);
        CryptographicOperations.ZeroMemory(ek);
        CryptographicOperations.ZeroMemory(mPrime);
        CryptographicOperations.ZeroMemory(kPrime);
        CryptographicOperations.ZeroMemory(rPrime);
        CryptographicOperations.ZeroMemory(cPrime);
        CryptographicOperations.ZeroMemory(z);

        var pinnedSharedSecret = new PinnedMemory<byte>(sharedSecret, zero: false, locked: true);
        CryptographicOperations.ZeroMemory(sharedSecret);
        return pinnedSharedSecret;
    }

    private KpkeKeyPair KpkeKeyGen(ReadOnlySpan<byte> d)
    {
        Span<byte> gIn = stackalloc byte[33];
        d.CopyTo(gIn);
        gIn[32] = (byte)_p.K;

        var gOut = Sha3_512(gIn);
        var rho = gOut.AsSpan(0, 32).ToArray();
        var sigma = gOut.AsSpan(32, 32).ToArray();

        var a = GenerateMatrix(rho, transpose: false);

        byte nonce = 0;
        var s = new short[_p.K][];
        var e = new short[_p.K][];

        for (var i = 0; i < _p.K; i++)
        {
            s[i] = SamplePolyCbd(Prf(sigma, nonce++, 64 * _p.Eta1), _p.Eta1);
        }

        for (var i = 0; i < _p.K; i++)
        {
            e[i] = SamplePolyCbd(Prf(sigma, nonce++, 64 * _p.Eta1), _p.Eta1);
        }

        var t = new short[_p.K][];
        for (var i = 0; i < _p.K; i++)
        {
            var acc = new short[N];
            for (var j = 0; j < _p.K; j++)
            {
                PolyAddInPlace(acc, PolyMul(a[i][j], s[j]));
            }
            PolyAddInPlace(acc, e[i]);
            t[i] = acc;
        }

        var ek = new byte[PublicKeyBytes];
        PackVector12(t, ek.AsSpan(0, _p.K * 384));
        rho.CopyTo(ek.AsSpan(_p.K * 384));

        var dkPke = new byte[_p.K * 384];
        PackVector12(s, dkPke);

        return new KpkeKeyPair(ek, dkPke);
    }

    private byte[] KpkeEncrypt(ReadOnlySpan<byte> ek, ReadOnlySpan<byte> message, ReadOnlySpan<byte> randomness)
    {
        var t = UnpackVector12(ek[..(_p.K * 384)], _p.K);
        var rho = ek[(_p.K * 384)..(_p.K * 384 + 32)].ToArray();

        var aT = GenerateMatrix(rho, transpose: true);

        byte nonce = 0;
        var r = new short[_p.K][];
        var e1 = new short[_p.K][];
        for (var i = 0; i < _p.K; i++)
        {
            r[i] = SamplePolyCbd(Prf(randomness, nonce++, 64 * _p.Eta1), _p.Eta1);
        }
        for (var i = 0; i < _p.K; i++)
        {
            e1[i] = SamplePolyCbd(Prf(randomness, nonce++, 64 * _p.Eta2), _p.Eta2);
        }

        var e2 = SamplePolyCbd(Prf(randomness, nonce++, 64 * _p.Eta2), _p.Eta2);

        var u = new short[_p.K][];
        for (var i = 0; i < _p.K; i++)
        {
            var acc = new short[N];
            for (var j = 0; j < _p.K; j++)
            {
                PolyAddInPlace(acc, PolyMul(aT[i][j], r[j]));
            }
            PolyAddInPlace(acc, e1[i]);
            u[i] = acc;
        }

        var v = new short[N];
        for (var j = 0; j < _p.K; j++)
        {
            PolyAddInPlace(v, PolyMul(t[j], r[j]));
        }
        PolyAddInPlace(v, e2);
        PolyAddInPlace(v, MessageToPoly(message));

        var c = new byte[CipherTextBytes];
        PackCompressedVector(u, _p.Du, c.AsSpan(0, _p.K * 32 * _p.Du));
        PackCompressedPoly(v, _p.Dv, c.AsSpan(_p.K * 32 * _p.Du));
        return c;
    }

    private byte[] KpkeDecrypt(ReadOnlySpan<byte> dkPke, ReadOnlySpan<byte> c)
    {
        var s = UnpackVector12(dkPke, _p.K);
        var u = UnpackCompressedVector(c[..(_p.K * 32 * _p.Du)], _p.K, _p.Du);
        var v = UnpackCompressedPoly(c[(_p.K * 32 * _p.Du)..], _p.Dv);

        var w = v.ToArray();
        for (var i = 0; i < _p.K; i++)
        {
            PolySubInPlace(w, PolyMul(s[i], u[i]));
        }

        return PolyToMessage(w);
    }

    private short[][][] GenerateMatrix(ReadOnlySpan<byte> rho, bool transpose)
    {
        var matrix = new short[_p.K][][];
        Span<byte> inBuf = stackalloc byte[34];
        rho.CopyTo(inBuf);

        for (var i = 0; i < _p.K; i++)
        {
            matrix[i] = new short[_p.K][];
            for (var j = 0; j < _p.K; j++)
            {
                var x = transpose ? j : i;
                var y = transpose ? i : j;
                inBuf[32] = (byte)x;
                inBuf[33] = (byte)y;
                matrix[i][j] = RejectionSampleFromShake128(inBuf, N);
            }
        }
        return matrix;
    }

    private static short[] RejectionSampleFromShake128(ReadOnlySpan<byte> shakeInput, int count)
    {
        var outPoly = new short[count];
        var outputLength = 672;

        while (true)
        {
            var bytes = Shake128(shakeInput, outputLength);
            if (TryRejectionSample(bytes, outPoly))
            {
                return outPoly;
            }

            outputLength += 168;
        }
    }

    private static bool TryRejectionSample(ReadOnlySpan<byte> bytes, Span<short> outPoly)
    {
        var pos = 0;
        for (var i = 0; i + 2 < bytes.Length && pos < outPoly.Length; i += 3)
        {
            var d1 = bytes[i] | ((bytes[i + 1] & 0x0F) << 8);
            var d2 = (bytes[i + 1] >> 4) | (bytes[i + 2] << 4);

            if (d1 < Q)
            {
                outPoly[pos++] = (short)d1;
            }
            if (pos < outPoly.Length && d2 < Q)
            {
                outPoly[pos++] = (short)d2;
            }
        }

        return pos == outPoly.Length;
    }

    private static short[] SamplePolyCbd(ReadOnlySpan<byte> bytes, int eta)
    {
        var outPoly = new short[N];
        var bitPos = 0;

        for (var i = 0; i < N; i++)
        {
            var a = 0;
            var b = 0;
            for (var j = 0; j < eta; j++)
            {
                a += GetBit(bytes, bitPos++);
            }
            for (var j = 0; j < eta; j++)
            {
                b += GetBit(bytes, bitPos++);
            }
            outPoly[i] = Reduce(a - b);
        }

        return outPoly;
    }

    private static int GetBit(ReadOnlySpan<byte> buf, int bitPos)
    {
        var b = buf[bitPos / 8];
        return (b >> (bitPos % 8)) & 1;
    }

    private static short[] MessageToPoly(ReadOnlySpan<byte> m)
    {
        var p = new short[N];
        for (var i = 0; i < N; i++)
        {
            var bit = (m[i / 8] >> (i % 8)) & 1;
            p[i] = bit == 1 ? (short)((Q + 1) / 2) : (short)0;
        }
        return p;
    }

    private static byte[] PolyToMessage(ReadOnlySpan<short> p)
    {
        var outBytes = new byte[32];
        for (var i = 0; i < N; i++)
        {
            var t = ((((Reduce(p[i]) << 1) + Q / 2) / Q) & 1);
            outBytes[i / 8] |= (byte)(t << (i % 8));
        }
        return outBytes;
    }

    private static void PackVector12(short[][] v, Span<byte> output)
    {
        for (var i = 0; i < v.Length; i++)
        {
            PackPoly12(v[i], output.Slice(i * 384, 384));
        }
    }

    private static short[][] UnpackVector12(ReadOnlySpan<byte> bytes, int k)
    {
        var v = new short[k][];
        for (var i = 0; i < k; i++)
        {
            v[i] = UnpackPoly12(bytes.Slice(i * 384, 384));
        }
        return v;
    }

    private static void PackPoly12(ReadOnlySpan<short> p, Span<byte> outBytes)
    {
        for (var i = 0; i < N / 2; i++)
        {
            var t0 = Reduce(p[2 * i]);
            var t1 = Reduce(p[2 * i + 1]);
            outBytes[3 * i] = (byte)t0;
            outBytes[3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));
            outBytes[3 * i + 2] = (byte)(t1 >> 4);
        }
    }

    private static short[] UnpackPoly12(ReadOnlySpan<byte> bytes)
    {
        var p = new short[N];
        for (var i = 0; i < N / 2; i++)
        {
            p[2 * i] = (short)(bytes[3 * i] | ((bytes[3 * i + 1] & 0x0F) << 8));
            p[2 * i + 1] = (short)((bytes[3 * i + 1] >> 4) | (bytes[3 * i + 2] << 4));
        }
        return p;
    }

    private static void PackCompressedVector(short[][] v, int d, Span<byte> outBytes)
    {
        var polyBytes = 32 * d;
        for (var i = 0; i < v.Length; i++)
        {
            PackCompressedPoly(v[i], d, outBytes.Slice(i * polyBytes, polyBytes));
        }
    }

    private static short[][] UnpackCompressedVector(ReadOnlySpan<byte> bytes, int k, int d)
    {
        var v = new short[k][];
        var polyBytes = 32 * d;
        for (var i = 0; i < k; i++)
        {
            v[i] = UnpackCompressedPoly(bytes.Slice(i * polyBytes, polyBytes), d);
        }
        return v;
    }

    private static void PackCompressedPoly(ReadOnlySpan<short> p, int d, Span<byte> outBytes)
    {
        var mask = (1 << d) - 1;
        var bitPos = 0;
        outBytes.Clear();
        for (var i = 0; i < N; i++)
        {
            var t = ((Reduce(p[i]) << d) + Q / 2) / Q;
            t &= mask;
            WriteBits(outBytes, bitPos, d, t);
            bitPos += d;
        }
    }

    private static short[] UnpackCompressedPoly(ReadOnlySpan<byte> bytes, int d)
    {
        var p = new short[N];
        var bitPos = 0;
        for (var i = 0; i < N; i++)
        {
            var t = ReadBits(bytes, bitPos, d);
            p[i] = (short)((t * Q + (1 << (d - 1))) >> d);
            bitPos += d;
        }
        return p;
    }

    private static void WriteBits(Span<byte> outBytes, int bitPos, int width, int value)
    {
        for (var i = 0; i < width; i++)
        {
            var bit = (value >> i) & 1;
            var p = bitPos + i;
            if (bit == 1)
            {
                outBytes[p / 8] |= (byte)(1 << (p % 8));
            }
        }
    }

    private static int ReadBits(ReadOnlySpan<byte> bytes, int bitPos, int width)
    {
        var value = 0;
        for (var i = 0; i < width; i++)
        {
            var p = bitPos + i;
            var bit = (bytes[p / 8] >> (p % 8)) & 1;
            value |= bit << i;
        }
        return value;
    }

    private static short[] PolyMul(ReadOnlySpan<short> a, ReadOnlySpan<short> b)
    {
        Span<int> tmp = stackalloc int[N];
        for (var i = 0; i < N; i++)
        {
            for (var j = 0; j < N; j++)
            {
                var prod = a[i] * b[j];
                var idx = i + j;
                if (idx < N)
                {
                    tmp[idx] += prod;
                }
                else
                {
                    tmp[idx - N] -= prod;
                }
            }
        }

        var outPoly = new short[N];
        for (var i = 0; i < N; i++)
        {
            outPoly[i] = Reduce(tmp[i]);
        }
        return outPoly;
    }

    private static void PolyAddInPlace(short[] acc, ReadOnlySpan<short> b)
    {
        if (ShouldUseSimd())
        {
            PolyAddInPlaceVectorized(acc, b);
            return;
        }

        PolyAddInPlaceScalar(acc, b);
    }

    private static void PolySubInPlace(short[] acc, ReadOnlySpan<short> b)
    {
        if (ShouldUseSimd())
        {
            PolySubInPlaceVectorized(acc, b);
            return;
        }

        PolySubInPlaceScalar(acc, b);
    }

    internal static double EstimatePolyArithmeticSpeedup(int iterations = 25_000)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        var lhs = new short[N];
        var rhs = new short[N];
        for (var i = 0; i < N; i++)
        {
            lhs[i] = (short)((i * 17 + 13) % Q);
            rhs[i] = (short)((i * 29 + 7) % Q);
        }

        var scalarMs = MeasurePolyArithmetic(iterations, lhs, rhs, useSimd: false);
        var simdMs = MeasurePolyArithmetic(iterations, lhs, rhs, useSimd: true);
        return scalarMs / simdMs;
    }

    private static bool ShouldUseSimd() => SimdExecutionMode switch
    {
        SimdMode.ForceEnabled => true,
        SimdMode.ForceDisabled => false,
        _ => Vector.IsHardwareAccelerated
    };

    private static double MeasurePolyArithmetic(int iterations, short[] lhs, short[] rhs, bool useSimd)
    {
        var acc = new short[N];
        var sink = 0;

        for (var i = 0; i < 1_000; i++)
        {
            Array.Copy(lhs, acc, N);
            if (useSimd)
            {
                PolyAddInPlaceVectorized(acc, rhs);
                PolySubInPlaceVectorized(acc, rhs);
            }
            else
            {
                PolyAddInPlaceScalar(acc, rhs);
                PolySubInPlaceScalar(acc, rhs);
            }
            sink ^= acc[i % N];
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
        {
            Array.Copy(lhs, acc, N);
            if (useSimd)
            {
                PolyAddInPlaceVectorized(acc, rhs);
                PolySubInPlaceVectorized(acc, rhs);
            }
            else
            {
                PolyAddInPlaceScalar(acc, rhs);
                PolySubInPlaceScalar(acc, rhs);
            }
            sink ^= acc[i % N];
        }
        sw.Stop();

        if (sink == int.MinValue)
        {
            throw new InvalidOperationException("Unreachable guard to prevent benchmark dead-code elimination.");
        }

        return sw.Elapsed.TotalMilliseconds;
    }

    private static void PolyAddInPlaceVectorized(short[] acc, ReadOnlySpan<short> b)
    {
        var i = 0;
        var width = Vector<short>.Count;
        var limit = N - width;
        Span<short> tmp = stackalloc short[Vector<short>.Count];

        for (; i <= limit; i += width)
        {
            var sum = new Vector<short>(acc, i) + new Vector<short>(b.Slice(i, width));
            sum.CopyTo(tmp);
            for (var j = 0; j < width; j++)
            {
                var value = tmp[j];
                acc[i + j] = (short)(value >= Q ? value - Q : value);
            }
        }

        for (; i < N; i++)
        {
            var sum = acc[i] + b[i];
            acc[i] = (short)(sum >= Q ? sum - Q : sum);
        }
    }

    private static void PolySubInPlaceVectorized(short[] acc, ReadOnlySpan<short> b)
    {
        var i = 0;
        var width = Vector<short>.Count;
        var limit = N - width;
        Span<short> tmp = stackalloc short[Vector<short>.Count];

        for (; i <= limit; i += width)
        {
            var diff = new Vector<short>(acc, i) - new Vector<short>(b.Slice(i, width));
            diff.CopyTo(tmp);
            for (var j = 0; j < width; j++)
            {
                var value = tmp[j];
                acc[i + j] = (short)(value < 0 ? value + Q : value);
            }
        }

        for (; i < N; i++)
        {
            var diff = acc[i] - b[i];
            acc[i] = (short)(diff < 0 ? diff + Q : diff);
        }
    }

    private static void PolyAddInPlaceScalar(short[] acc, ReadOnlySpan<short> b)
    {
        for (var i = 0; i < N; i++)
        {
            var sum = acc[i] + b[i];
            acc[i] = (short)(sum >= Q ? sum - Q : sum);
        }
    }

    private static void PolySubInPlaceScalar(short[] acc, ReadOnlySpan<short> b)
    {
        for (var i = 0; i < N; i++)
        {
            var diff = acc[i] - b[i];
            acc[i] = (short)(diff < 0 ? diff + Q : diff);
        }
    }

    private static short Reduce(int x)
    {
        var r = x % Q;
        if (r < 0)
        {
            r += Q;
        }
        return (short)r;
    }

    private static byte[] Prf(ReadOnlySpan<byte> seed, byte nonce, int outLen)
    {
        Span<byte> input = stackalloc byte[33];
        seed.CopyTo(input);
        input[32] = nonce;
        return Shake256(input, outLen);
    }

    private static byte[] Sha3_256(ReadOnlySpan<byte> input) => Keccak.Hash(input, 136, 32, 0x06);
    private static byte[] Sha3_512(ReadOnlySpan<byte> input) => Keccak.Hash(input, 72, 64, 0x06);
    private static byte[] Shake128(ReadOnlySpan<byte> input, int outLen) => Keccak.Hash(input, 168, outLen, 0x1F);
    private static byte[] Shake256(ReadOnlySpan<byte> input, int outLen) => Keccak.Hash(input, 136, outLen, 0x1F);

    private sealed record Parameters(int K, int Eta1, int Eta2, int Du, int Dv);
    private readonly record struct KpkeKeyPair(byte[] PublicKey, byte[] SecretKey);
}

internal static class Keccak
{
    private static readonly int[] RotationOffsets =
    {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };

    private static readonly ulong[] RoundConstants =
    {
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808AUL, 0x8000000080008000UL,
        0x000000000000808BUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008AUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800AUL, 0x800000008000000AUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL
    };

    public static byte[] Hash(ReadOnlySpan<byte> input, int rate, int outputLength, byte delimitedSuffix)
    {
        var state = new ulong[25];

        var inputOffset = 0;
        while (input.Length - inputOffset >= rate)
        {
            AbsorbBlock(state, input.Slice(inputOffset, rate));
            Permute(state);
            inputOffset += rate;
        }

        Span<byte> finalBlock = stackalloc byte[200];
        finalBlock.Clear();
        var remaining = input.Length - inputOffset;
        input.Slice(inputOffset, remaining).CopyTo(finalBlock);
        finalBlock[remaining] ^= delimitedSuffix;
        finalBlock[rate - 1] ^= 0x80;

        AbsorbBlock(state, finalBlock[..rate]);
        Permute(state);

        var output = new byte[outputLength];
        var outOffset = 0;
        while (outOffset < outputLength)
        {
            var blockLen = Math.Min(rate, outputLength - outOffset);
            SqueezeBlock(state, output.AsSpan(outOffset, blockLen));
            outOffset += blockLen;
            if (outOffset < outputLength)
            {
                Permute(state);
            }
        }

        return output;
    }

    private static void AbsorbBlock(ulong[] state, ReadOnlySpan<byte> block)
    {
        for (var i = 0; i < block.Length / 8; i++)
        {
            state[i] ^= ReadUInt64LittleEndian(block.Slice(i * 8, 8));
        }
    }

    private static void SqueezeBlock(ulong[] state, Span<byte> output)
    {
        for (var i = 0; i < output.Length; i++)
        {
            var lane = i / 8;
            var shift = (i % 8) * 8;
            output[i] = (byte)(state[lane] >> shift);
        }
    }

    private static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> src)
    {
        ulong value = 0;
        for (var i = 0; i < 8; i++)
        {
            value |= ((ulong)src[i]) << (8 * i);
        }
        return value;
    }

    private static void Permute(ulong[] a)
    {
        Span<ulong> b = stackalloc ulong[25];
        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> d = stackalloc ulong[5];

        for (var round = 0; round < 24; round++)
        {
            for (var x = 0; x < 5; x++)
            {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            for (var x = 0; x < 5; x++)
            {
                d[x] = c[(x + 4) % 5] ^ RotateLeft(c[(x + 1) % 5], 1);
            }

            for (var i = 0; i < 25; i++)
            {
                a[i] ^= d[i % 5];
            }

            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    var idx = x + 5 * y;
                    var newX = y;
                    var newY = (2 * x + 3 * y) % 5;
                    b[newX + 5 * newY] = RotateLeft(a[idx], RotationOffsets[idx]);
                }
            }

            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    a[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
                }
            }

            a[0] ^= RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong x, int n) => (x << n) | (x >> (64 - n));
}
