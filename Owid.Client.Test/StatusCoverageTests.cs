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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// One case per failure the vocabulary can report.
    /// </summary>
    /// <remarks>
    /// Every failure condition gets a test. Where a status cannot be reached
    /// in .NET the reason is recorded here and on the member itself, so a gap
    /// is a stated decision rather than something nobody noticed. The last
    /// test walks both vocabularies and fails when a member is neither
    /// produced nor named unreachable, so one cannot be added later and left
    /// silently untested.
    /// </remarks>
    [TestClass]
    public class StatusCoverageTests
    {
        private const string TestDomain = "51degrees.com";

        private const string PrivatePEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n" +
            "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n" +
            "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n" +
            "-----END PRIVATE KEY-----";

        private static readonly HashSet<OwidParseStatus> ReachedParse = new();

        private static readonly HashSet<OwidSignatureStatus> ReachedSignature
            = new();

        private static Model.Owid Create(byte[] payload)
        {
            using var crypto = ECDsa.Create();
            crypto.ImportFromPem(PrivatePEM);
            return new Creator(TestDomain, crypto).Create(payload);
        }

        /// <summary>
        /// Asserts the whole of what the contract promises on failure, and
        /// records which status was reached.
        /// </summary>
        private static void Refuse(byte[] buffer, OwidParseStatus want)
        {
            Assert.IsFalse(
                Model.Owid.TryParse(buffer, out var owid, out var status));
            Assert.IsNull(owid, "no value is handed back on failure");
            Assert.AreEqual(want, status);
            ReachedParse.Add(status);
        }

        [TestMethod]
        public void EveryParseFailureIsReported()
        {
            var good = Create(new byte[] { 1, 2, 3 }).AsByteArray();
            ReachedParse.Add(OwidParseStatus.Parsed);

            Refuse(Array.Empty<byte>(), OwidParseStatus.MissingInput);

            // Version 0 stands for an absent node inside a stream. It carries
            // no domain, date, payload or signature, so it can never verify,
            // and letting one through would be the single case of an instance
            // with no signature reaching a caller.
            Refuse(new byte[] { 0 }, OwidParseStatus.UnsupportedVersion);

            var unknown = (byte[])good.Clone();
            unknown[0] = 9;
            Refuse(unknown, OwidParseStatus.UnsupportedVersion);

            // Data that stops inside a field, before the declared length is
            // even read. Distinct from a declaration disagreeing with data
            // that is all present.
            Refuse(good.Take(3).ToArray(), OwidParseStatus.UnexpectedEnd);

            // A domain that never terminates within the published maximum.
            var domain = new byte[301];
            domain[0] = (byte)OwidVersion.Version3;
            for (var i = 1; i < domain.Length; i++)
            {
                domain[i] = (byte)'a';
            }
            Refuse(domain, OwidParseStatus.InvalidDomainEncoding);

            Refuse(
                good.Concat(new byte[] { 0 }).ToArray(),
                OwidParseStatus.ByteCountMismatch);

            // The declared payload cannot leave exactly the signature the
            // version requires, which is the finding whichever way the bytes
            // fall short.
            Refuse(
                good.Take(good.Length - 1).ToArray(),
                OwidParseStatus.ByteCountMismatch);

            Assert.IsFalse(Model.Owid.TryParse(
                "not base 64 at all!!", out _, out var encoded));
            Assert.AreEqual(OwidParseStatus.InvalidBase64, encoded);
            ReachedParse.Add(encoded);
        }

        [TestMethod]
        public void EverySignatureOutcomeIsReported()
        {
            var owid = Create(new byte[] { 1, 2, 3 });
            using var crypto = ECDsa.Create();
            crypto.ImportFromPem(PrivatePEM);
            var pem = crypto.ExportSubjectPublicKeyInfoPem();

            Record(
                owid.SignatureStatus(pem),
                OwidSignatureStatus.SignatureValid);

            var raw = owid.AsByteArray();
            raw[raw.Length - 1] ^= 0xFF;
            Assert.IsTrue(Model.Owid.TryParse(raw, out var tampered, out _));
            Record(
                tampered!.SignatureStatus(pem),
                OwidSignatureStatus.SignatureInvalid);

            Record(
                owid.SignatureStatus(string.Empty),
                OwidSignatureStatus.KeyUnavailable);

            // The case that happened. On 30 August 2026 the key endpoints
            // served PEM a strict parser rejects, and reporting that as a
            // forgery would have read as an attack rather than the outage it
            // was.
            Record(
                owid.SignatureStatus(
                    "-----BEGIN PUBLIC KEY-----\nnot base 64\n"
                    + "-----END PUBLIC KEY-----"),
                OwidSignatureStatus.InvalidKey);
        }

        private static void Record(
            OwidSignatureStatus got,
            OwidSignatureStatus want)
        {
            Assert.AreEqual(want, got);
            ReachedSignature.Add(got);
        }

        [TestMethod]
        public void EveryStatusIsCoveredOrNamedUnreachable()
        {
            // Run the two producing tests first, so this does not depend on
            // the order the runner happens to choose.
            EveryParseFailureIsReported();
            EverySignatureOutcomeIsReported();

            // Kept as guards rather than removed, because the arithmetic they
            // back up could change, and because a status that must never be
            // reported as a forgery is worth keeping even when nothing
            // produces it today.
            var unreachableParse = new[]
            {
                // The compiler already refuses anything but a string or a
                // byte array on these surfaces.
                OwidParseStatus.InvalidInputType,
                // An array index cannot exceed the declaration that the count
                // check has already refused.
                OwidParseStatus.ImplementationCapacityExceeded,
                // No path while the byte count rule holds.
                OwidParseStatus.MalformedEnvelope,
            };
            var unreachableSignature = new[]
            {
                // A parse only succeeds with a signature of exactly the
                // required length, so nothing arriving by either allowed
                // route can carry the wrong one.
                OwidSignatureStatus.InvalidSignatureLength,
                // Needs the provider to fail on inputs that are themselves
                // fine.
                OwidSignatureStatus.VerificationError,
                // Needs more data than this runtime can hold.
                OwidSignatureStatus.ImplementationCapacityExceeded,
            };

            foreach (OwidParseStatus status in
                Enum.GetValues(typeof(OwidParseStatus)))
            {
                Assert.IsTrue(
                    ReachedParse.Contains(status)
                        || unreachableParse.Contains(status),
                    $"{status} is neither tested nor named unreachable");
            }

            foreach (OwidSignatureStatus status in
                Enum.GetValues(typeof(OwidSignatureStatus)))
            {
                Assert.IsTrue(
                    ReachedSignature.Contains(status)
                        || unreachableSignature.Contains(status),
                    $"{status} is neither tested nor named unreachable");
            }
        }
    }
}
