/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;
using System;
using System.IO;
using System.Text;

namespace Owid.Client.Test
{
    /// <summary>
    /// The payload length field of an OWID is whatever the sender declared,
    /// so parsing must check it against the bytes present before sizing
    /// anything by it. These tests prove that a declared length that does
    /// not leave exactly the signature after the payload is refused, that
    /// refusing it costs no allocation sized by the declared number, and
    /// that a correctly sized envelope still parses. The 64 byte signature
    /// is the fixed tail every valid OWID ends with.
    /// </summary>
    [TestClass]
    public class PayloadLengthTests
    {
        private const int SignatureLength = 64;

        /// <summary>
        /// A version 3 envelope, being the version byte, the domain with its
        /// terminator, four minute bytes, the declared payload length, the
        /// payload bytes given and the signature bytes given, so a test can
        /// make the declared length and the bytes present disagree.
        /// </summary>
        private static byte[] Envelope(
            uint declaredLength, byte[] payload, byte[] signature)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)OwidVersion.Version3);
                writer.Write(Encoding.ASCII.GetBytes("51d.es"));
                writer.Write((byte)0);
                writer.Write((uint)1000);
                writer.Write(declaredLength);
                writer.Write(payload);
                writer.Write(signature);
                writer.Flush();
                return stream.ToArray();
            }
        }

        private static byte[] Filled(int length, byte value)
        {
            var bytes = new byte[length];
            for (var i = 0; i < length; i++) { bytes[i] = value; }
            return bytes;
        }

        private static readonly byte[] Payload = Filled(37, 0x5A);
        private static readonly byte[] Signature = Filled(SignatureLength, 0x99);

        /// <summary>
        /// The declared length matches the bytes present, the signature is
        /// the last 64 bytes, and the envelope parses to the same payload.
        /// </summary>
        [TestMethod]
        public void DeclaredLengthMatches_Parses()
        {
            var owid = new Model.Owid(Envelope((uint)Payload.Length, Payload, Signature));
            CollectionAssert.AreEqual(Payload, owid.Payload);
            CollectionAssert.AreEqual(Signature, owid.Signature);
            Assert.AreEqual("51d.es", owid.Domain);
        }

        /// <summary>
        /// A payload materially larger than an ordinary identifier remains
        /// valid when its declaration and bytes agree. This guards against
        /// turning an application policy into a format restriction.
        /// </summary>
        [TestMethod]
        public void MatchingOneMebibytePayload_Parses()
        {
            var payload = Filled(1024 * 1024, 0x5A);
            var owid = new Model.Owid(
                Envelope((uint)payload.Length, payload, Signature));

            CollectionAssert.AreEqual(payload, owid.Payload);
        }

        /// <summary>
        /// A round trip through the library's own writer still parses, so
        /// the check agrees with what the library itself produces.
        /// </summary>
        [TestMethod]
        public void LibraryOutput_Parses()
        {
            var original = new Model.Owid
            {
                Domain = "51d.es",
                Payload = Payload,
                Signature = Signature,
            };
            var parsed = new Model.Owid(original.AsByteArray());
            CollectionAssert.AreEqual(Payload, parsed.Payload);
        }

        /// <summary>
        /// One more or one fewer than the bytes present is refused, because
        /// either leaves something other than exactly the signature at the
        /// end.
        /// </summary>
        [TestMethod]
        public void DeclaredLengthOffByOne_IsRefused()
        {
            foreach (var declared in new[] { Payload.Length - 1, Payload.Length + 1 })
            {
                var bytes = Envelope((uint)declared, Payload, Signature);
                Assert.ThrowsExactly<Exception>(
                    () => new Model.Owid(bytes), $"declared {declared}");
            }
        }

        /// <summary>
        /// A byte after the signature is refused, because the signature
        /// must be the end of the envelope.
        /// </summary>
        [TestMethod]
        public void TrailingByteAfterSignature_IsRefused()
        {
            var bytes = Envelope((uint)Payload.Length, Payload, Signature);
            var longer = new byte[bytes.Length + 1];
            Array.Copy(bytes, longer, bytes.Length);
            Assert.ThrowsExactly<Exception>(() => new Model.Owid(longer));
        }

        /// <summary>
        /// A short signature is refused. The declared payload length is
        /// right for the payload, but the bytes after it are fewer than a
        /// signature.
        /// </summary>
        [TestMethod]
        public void ShortSignature_IsRefused()
        {
            var bytes = Envelope(
                (uint)Payload.Length, Payload, Filled(SignatureLength - 1, 0x99));
            Assert.ThrowsExactly<Exception>(() => new Model.Owid(bytes));
        }

        /// <summary>
        /// A large declaration whose payload bytes are absent is refused
        /// without an allocation sized by the declared number. The envelope
        /// is a few dozen bytes while declaring 64 MiB, then 2 GiB, then
        /// more than an int can hold, and each parse allocates under 64 KiB.
        /// The numeric values remain valid when the matching payload is
        /// present.
        /// </summary>
        [TestMethod]
        public void MismatchedLargeDeclaration_IsRefusedWithoutAllocating()
        {
            foreach (var declared in new uint[]
            {
                64u * 1024 * 1024,
                int.MaxValue - 100,
                int.MaxValue,
                uint.MaxValue,
            })
            {
                var bytes = Envelope(declared, Array.Empty<byte>(), Array.Empty<byte>());
                var before = GC.GetAllocatedBytesForCurrentThread();
                Assert.ThrowsExactly<Exception>(
                    () => new Model.Owid(bytes), $"declared {declared}");
                var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
                Assert.IsTrue(
                    allocated < 64 * 1024,
                    $"declared {declared} allocated {allocated} bytes");
            }
        }

        /// <summary>
        /// A stream whose length cannot be asked for is read in bounded
        /// pieces: a matching envelope parses, and a declared length beyond
        /// the bytes present is refused without allocating the declared
        /// amount.
        /// </summary>
        [TestMethod]
        public void NonSeekableStream_IsBoundedByTheBytesPresent()
        {
            var good = Envelope((uint)Payload.Length, Payload, Signature);
            var parsed = new Model.Owid();
            using (var reader = new BinaryReader(new ForwardOnlyStream(good)))
            {
                parsed.Version = (OwidVersion)reader.ReadByte();
                parsed.FromBuffer(reader);
            }
            CollectionAssert.AreEqual(Payload, parsed.Payload);

            var mismatched = Envelope(
                64u * 1024 * 1024,
                Array.Empty<byte>(),
                Array.Empty<byte>());
            var before = GC.GetAllocatedBytesForCurrentThread();
            using (var reader = new BinaryReader(
                new ForwardOnlyStream(mismatched)))
            {
                var owid = new Model.Owid { Version = (OwidVersion)reader.ReadByte() };
                Assert.ThrowsExactly<Exception>(() => owid.FromBuffer(reader));
            }
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.IsTrue(allocated < 64 * 1024, $"allocated {allocated} bytes");
        }

        /// <summary>
        /// A matching payload from a forward-only source is collected in
        /// fixed pieces and copied once into its final array. The allocation
        /// stays close to twice the actual payload size and does not include
        /// MemoryStream growth plus a further ToArray copy.
        /// </summary>
        [TestMethod]
        public void NonSeekableLargePayload_AvoidsGrowingBufferCopy()
        {
            var payload = Filled(1024 * 1024, 0x5A);
            var bytes = Envelope((uint)payload.Length, payload, Signature);
            var parsed = new Model.Owid();
            var before = GC.GetAllocatedBytesForCurrentThread();

            using (var reader = new BinaryReader(new ForwardOnlyStream(bytes)))
            {
                parsed.Version = (OwidVersion)reader.ReadByte();
                parsed.FromBuffer(reader);
            }

            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            CollectionAssert.AreEqual(payload, parsed.Payload);
            Assert.IsTrue(
                allocated < 2300L * 1024,
                $"reading {payload.Length} bytes allocated {allocated} bytes");
        }

        /// <summary>
        /// The public reader consumes one OWID and leaves following framed
        /// bytes untouched, preserving its established stream-composition
        /// behaviour. The byte-array constructor remains strict about EOF.
        /// </summary>
        [TestMethod]
        public void FromBuffer_LeavesAFollowingEnvelopeUnread()
        {
            var firstBytes = Envelope((uint)Payload.Length, Payload, Signature);
            var secondBytes = Envelope(0, Array.Empty<byte>(), Signature);
            var framed = new byte[firstBytes.Length + secondBytes.Length];
            Array.Copy(firstBytes, framed, firstBytes.Length);
            Array.Copy(secondBytes, 0, framed, firstBytes.Length, secondBytes.Length);

            using (var stream = new MemoryStream(framed))
            using (var reader = new BinaryReader(stream))
            {
                var first = new Model.Owid
                {
                    Version = (OwidVersion)reader.ReadByte(),
                };
                first.FromBuffer(reader);

                Assert.AreEqual(firstBytes.Length, stream.Position);
                CollectionAssert.AreEqual(Payload, first.Payload);

                var second = new Model.Owid
                {
                    Version = (OwidVersion)reader.ReadByte(),
                };
                second.FromBuffer(reader);
                Assert.AreEqual(framed.Length, stream.Position);
                Assert.AreEqual(0, second.Payload.Length);
            }
        }

        /// <summary>
        /// A read-only stream that reports it cannot seek, so the parser has
        /// to take the bounded path.
        /// </summary>
        private sealed class ForwardOnlyStream : Stream
        {
            private readonly MemoryStream _inner;

            public ForwardOnlyStream(byte[] bytes)
            {
                _inner = new MemoryStream(bytes);
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count)
                => _inner.Read(buffer, offset, count);
            public override long Seek(long offset, SeekOrigin origin)
                => throw new NotSupportedException();
            public override void SetLength(long value)
                => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing) { _inner.Dispose(); }
                base.Dispose(disposing);
            }
        }
    }
}
