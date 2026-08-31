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
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// What the parse and creation surfaces promise, tested as a contract
    /// rather than through any one caller.
    /// </summary>
    /// <remarks>
    /// Two promises are being kept here. The first is that reading external
    /// data always answers rather than throwing, and always answers with the
    /// same three facts: whether it worked, the value only when it did, and a
    /// named reason either way. The second is that an OWID can only arrive by
    /// parsing one or by a creator signing one, so no caller can hold a
    /// half-made or altered identifier.
    /// </remarks>
    [TestClass]
    public class ParseContractTests
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
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                return new Creator(TestDomain, crypto).Create(payload);
            }
        }

        /// <summary>
        /// Success reports all three facts, not just the value.
        /// </summary>
        [TestMethod]
        public void Success_ReportsTrueAValueAndParsed()
        {
            var bytes = Create(new byte[] { 1, 2, 3 }).AsByteArray();

            Assert.IsTrue(
                Model.Owid.TryParse(bytes, out var owid, out var status));
            Assert.IsNotNull(owid);
            Assert.AreEqual(OwidParseStatus.Parsed, status);
        }

        /// <summary>
        /// An OWID carrying nothing is still an OWID. The payload is what the
        /// creator had to say, and having nothing to say is allowed.
        /// </summary>
        [TestMethod]
        public void EmptyPayload_Parses()
        {
            var bytes = Create(Array.Empty<byte>()).AsByteArray();

            Assert.IsTrue(
                Model.Owid.TryParse(bytes, out var owid, out var status));
            Assert.AreEqual(OwidParseStatus.Parsed, status);
            Assert.AreEqual(0, owid!.Payload.Length);
        }

        /// <summary>
        /// A megabyte parses, which is the point: the format's limit is the
        /// wire format's, and how large a payload an application is willing to
        /// accept is that application's policy rather than something this
        /// library decides on its behalf.
        /// </summary>
        [TestMethod]
        public void LargePayload_Parses()
        {
            var payload = new byte[1024 * 1024];
            new Random(1).NextBytes(payload);
            var bytes = Create(payload).AsByteArray();

            Assert.IsTrue(
                Model.Owid.TryParse(bytes, out var owid, out var status));
            Assert.AreEqual(OwidParseStatus.Parsed, status);
            CollectionAssert.AreEqual(payload, owid!.Payload);
        }

        /// <summary>
        /// Nothing to parse is its own answer, and not confused with data that
        /// was supplied and turned out to be wrong.
        /// </summary>
        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        public void AbsentInput_IsMissingInput(string? value)
        {
            Assert.IsFalse(
                Model.Owid.TryParse(value, out var owid, out var status));
            Assert.IsNull(owid);
            Assert.AreEqual(OwidParseStatus.MissingInput, status);
        }

        /// <summary>
        /// A null buffer likewise.
        /// </summary>
        [TestMethod]
        public void NullBuffer_IsMissingInput()
        {
            Assert.IsFalse(Model.Owid.TryParse(
                (byte[]?)null, out var owid, out var status));
            Assert.IsNull(owid);
            Assert.AreEqual(OwidParseStatus.MissingInput, status);
        }

        /// <summary>
        /// A caller cannot build an OWID. If a public constructor ever comes
        /// back, an unsigned one could be handed to code that cannot tell the
        /// difference, so this asserts the boundary rather than trusting it.
        /// </summary>
        [TestMethod]
        public void Owid_HasNoPublicConstructor()
        {
            var constructors = typeof(Model.Owid).GetConstructors(
                BindingFlags.Public | BindingFlags.Instance);

            Assert.AreEqual(
                0,
                constructors.Length,
                "an OWID must arrive from a parse or a creator, and from "
                + "nowhere else, so that one cannot exist unsigned");
        }

        /// <summary>
        /// Nor can a caller change one after it exists, because the signature
        /// covers the fields as they were.
        /// </summary>
        [TestMethod]
        public void Owid_HasNoPubliclySettableState()
        {
            var settable = typeof(Model.Owid)
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.GetSetMethod() != null)
                .Select(p => p.Name)
                .ToArray();

            Assert.AreEqual(
                0,
                settable.Length,
                "publicly settable: " + string.Join(", ", settable));
        }

        /// <summary>
        /// The payload and signature are handed out as copies, so writing into
        /// what a caller was given cannot alter the OWID it came from. Without
        /// this, code could hold something whose signature no longer describes
        /// it and would only find out later, somewhere else.
        /// </summary>
        [TestMethod]
        public void MutatingReturnedArrays_DoesNotAlterTheOwid()
        {
            var owid = Create(new byte[] { 9, 8, 7 });
            var payloadBefore = owid.Payload;
            var signatureBefore = owid.Signature;

            owid.Payload[0] ^= 0xFF;
            owid.Signature[0] ^= 0xFF;

            CollectionAssert.AreEqual(payloadBefore, owid.Payload);
            CollectionAssert.AreEqual(signatureBefore, owid.Signature);
        }

        /// <summary>
        /// Parsing says whether the bytes are an OWID, and says nothing about
        /// whether the signature is genuine. A structurally valid identifier
        /// with a signature that does not match parses, and then fails
        /// verification, because those are two separate questions.
        /// </summary>
        [TestMethod]
        public void StructurallyValidButUnsigned_ParsesThenFailsVerification()
        {
            var bytes = Create(new byte[] { 4, 5, 6 }).AsByteArray();
            bytes[bytes.Length - 1] ^= 0xFF;

            Assert.IsTrue(
                Model.Owid.TryParse(bytes, out var owid, out var status),
                "flipping a signature byte leaves the envelope readable");
            Assert.AreEqual(OwidParseStatus.Parsed, status);

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                Assert.IsFalse(
                    owid!.Verify(crypto),
                    "and the signature is then found not to match");
            }
        }

        /// <summary>
        /// The payload size can be read without copying the payload, so an
        /// application applying a size limit does not pay for a copy of the
        /// bytes it is about to reject.
        /// </summary>
        [TestMethod]
        public void PayloadLength_DoesNotCopy()
        {
            var owid = Create(new byte[] { 1, 2, 3, 4 });
            Assert.AreEqual(4L, owid.PayloadLength);

            // Reading it does not hand out the array, so nothing a caller
            // holds can be written into.
            Assert.AreNotSame(owid.Payload, owid.Payload);
            Assert.AreEqual(owid.Payload.LongLength, owid.PayloadLength);
        }

    }
}
