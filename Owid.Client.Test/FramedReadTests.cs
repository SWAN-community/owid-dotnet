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

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// Reading one envelope from a stream that carries more after it.
    /// </summary>
    /// <remarks>
    /// This capability existed before and became unreachable when
    /// construction closed, because the only way in took an OWID to populate
    /// and callers can no longer make one. It compiled and no caller could
    /// use it, which is the same way a capability was lost in the Go port.
    /// </remarks>
    [TestClass]
    public class FramedReadTests
    {
        private const string TestDomain = "51degrees.com";

        private const string PrivatePEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n" +
            "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n" +
            "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n" +
            "-----END PRIVATE KEY-----";

        private static Model.Owid Create(byte[] payload)
        {
            using var crypto = ECDsa.Create();
            crypto.ImportFromPem(PrivatePEM);
            return new Creator(TestDomain, crypto).Create(payload);
        }

        /// <summary>
        /// Two envelopes in one stream read back as two, which is the whole
        /// point of the framed contract.
        /// </summary>
        [TestMethod]
        public void TwoEnvelopesInAStreamReadBackAsTwo()
        {
            var first = Create(new byte[] { 1, 2, 3 }).AsByteArray();
            var second = Create(new byte[] { 4, 5 }).AsByteArray();
            using var stream = new MemoryStream(
                first.Concat(second).ToArray());

            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var one, out var firstStatus));
            Assert.AreEqual(OwidParseStatus.Parsed, firstStatus);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, one!.Payload);

            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var two, out var secondStatus));
            Assert.AreEqual(OwidParseStatus.Parsed, secondStatus);
            CollectionAssert.AreEqual(new byte[] { 4, 5 }, two!.Payload);

            // And the stream is now empty, which a caller reading a sequence
            // finds out by being told nothing was supplied.
            Assert.IsFalse(
                Model.Owid.TryRead(stream, out var none, out var endStatus));
            Assert.IsNull(none);
            Assert.AreEqual(OwidParseStatus.MissingInput, endStatus);
        }

        /// <summary>
        /// The version 0 marker stands for an absent node inside a stream, so
        /// a run of envelopes with a gap in it reads back as an envelope, an
        /// absent node, and the next envelope. Getting this wrong stops the
        /// walk dead, because a caller that cannot tell a gap from rubbish has
        /// no way to reach whatever follows the gap.
        /// </summary>
        [TestMethod]
        public void AMarkerIsSteppedOverAndTheNextEnvelopeIsRead()
        {
            var first = Create(new byte[] { 1, 2, 3 }).AsByteArray();
            var second = Create(new byte[] { 4, 5 }).AsByteArray();
            using var stream = new MemoryStream(first
                .Concat(new byte[] { (byte)OwidVersion.Empty })
                .Concat(second)
                .ToArray());

            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var one, out var firstStatus));
            Assert.AreEqual(OwidParseStatus.Parsed, firstStatus);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, one!.Payload);

            // The marker is named for what it is, and no value comes back
            // because it carries no signature and could never verify.
            Assert.IsFalse(
                Model.Owid.TryRead(stream, out var gap, out var gapStatus));
            Assert.IsNull(gap);
            Assert.AreEqual(OwidParseStatus.AbsentNode, gapStatus);

            // Its one byte has been taken, so the next read starts on the next
            // envelope rather than part way into it.
            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var two, out var secondStatus));
            Assert.AreEqual(OwidParseStatus.Parsed, secondStatus);
            CollectionAssert.AreEqual(new byte[] { 4, 5 }, two!.Payload);
        }

        /// <summary>
        /// Two markers in a row are two absent nodes, not one.
        /// </summary>
        [TestMethod]
        public void TwoMarkersInARowAreTwoAbsentNodes()
        {
            using var stream = new MemoryStream(new byte[] { 0, 0 });
            for (var i = 0; i < 2; i++)
            {
                Assert.IsFalse(
                    Model.Owid.TryRead(stream, out var owid, out var status));
                Assert.IsNull(owid);
                Assert.AreEqual(OwidParseStatus.AbsentNode, status);
            }
            Assert.IsFalse(
                Model.Owid.TryRead(stream, out _, out var endStatus));
            Assert.AreEqual(OwidParseStatus.MissingInput, endStatus);
        }

        /// <summary>
        /// The same two envelopes are not one whole OWID. This is the single
        /// place the two contracts differ: in a buffer nothing else could own
        /// the trailing bytes, so they are a disagreement, while in a stream
        /// they may be the next envelope.
        /// </summary>
        [TestMethod]
        public void TheSameBytesAreRefusedAsOneWholeOwid()
        {
            var both = Create(new byte[] { 1, 2, 3 }).AsByteArray()
                .Concat(Create(new byte[] { 4, 5 }).AsByteArray())
                .ToArray();

            Assert.IsFalse(
                Model.Owid.TryParse(both, out var owid, out var status));
            Assert.IsNull(owid);
            Assert.AreEqual(OwidParseStatus.ByteCountMismatch, status);
        }

        /// <summary>
        /// A stream that stops before the signature is refused, and says the
        /// data ended early rather than that a declaration disagreed with data
        /// that is all present. On this contract nothing can be said about a
        /// disagreement, because what follows is not the parse's to judge, so
        /// the only certain fact is that the declared bytes never arrived.
        /// </summary>
        [TestMethod]
        public void AStreamThatStopsBeforeTheSignatureIsRefused()
        {
            var whole = Create(new byte[] { 1, 2, 3 }).AsByteArray();
            using var stream = new MemoryStream(
                whole.Take(whole.Length - 10).ToArray());

            Assert.IsFalse(
                Model.Owid.TryRead(stream, out var owid, out var status));
            Assert.IsNull(owid);
            // Data stopping early, not a declaration disagreeing with data
            // that is all present. A caller reading from a source still
            // arriving needs to know whether waiting would help.
            Assert.AreEqual(OwidParseStatus.UnexpectedEnd, status);
        }

        /// <summary>
        /// A forward only source, which cannot answer how much is left, still
        /// works. That is the capability worth keeping: without it a caller
        /// would have to buffer a whole stream before reading any of it.
        /// </summary>
        [TestMethod]
        public void AForwardOnlySourceStillWorks()
        {
            var whole = Create(new byte[] { 9, 8, 7 }).AsByteArray();
            using var stream = new PayloadLengthTests.ForwardOnlyStream(whole);

            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var owid, out var status));
            Assert.AreEqual(OwidParseStatus.Parsed, status);
            CollectionAssert.AreEqual(new byte[] { 9, 8, 7 }, owid!.Payload);
        }

        /// <summary>
        /// A declared payload far larger than the bytes present must not
        /// decide the allocation. The sender chooses that number, so a reader
        /// that sized anything by it would let them choose how much memory it
        /// takes before any data justified it.
        /// </summary>
        [TestMethod]
        public void ALargeDeclarationDoesNotAllocateBeforeTheBytesArrive()
        {
            // A version byte, a one character domain, a date, then a
            // declaration of 64 MiB with nothing behind it.
            var head = new byte[] { (byte)OwidVersion.Version3, (byte)'a', 0 }
                .Concat(new byte[] { 0, 0, 0, 0 })
                .Concat(BitConverter.GetBytes(64u * 1024 * 1024))
                .ToArray();

            var before = GC.GetAllocatedBytesForCurrentThread();
            using (var stream = new PayloadLengthTests.ForwardOnlyStream(head))
            {
                Assert.IsFalse(
                    Model.Owid.TryRead(stream, out var owid, out var status));
                Assert.IsNull(owid);
                Assert.AreEqual(OwidParseStatus.UnexpectedEnd, status);
            }
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            Assert.IsTrue(
                allocated < 64 * 1024,
                $"a 64 MiB declaration allocated {allocated} bytes");
        }
    }
}
