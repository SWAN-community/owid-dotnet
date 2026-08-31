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
using Owid.Client.Model.Configuration;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Owid.Client.Test
{
    /// <summary>
    /// The creator domain of an OWID ends at a zero terminator that the
    /// sender supplies, so parsing must stop looking for it at the longest
    /// a domain is allowed to be rather than at the end of the buffer.
    /// These tests prove that a domain of the published maximum still
    /// parses, that a longer one is refused, and that a buffer with no
    /// terminator at all is refused for a fixed cost however many bytes it
    /// carries. The maximum is 253 characters, which RFC 1035 section 2.3.4
    /// gives as 255 octets on the wire less the label length octet the
    /// first label has no dot for and the zero octet for the root, neither
    /// of which has a text form.
    ///
    /// The same maximum binds the write, so the library cannot produce an
    /// OWID it would itself refuse to parse. The tests below prove that a
    /// creator takes a domain of the maximum and refuses a longer one when
    /// it is given, that serialising refuses a longer one that arrived by
    /// some other route, and that both refusals happen before the key is
    /// used.
    /// </summary>
    [TestClass]
    public class DomainLengthTests
    {
        private const int SignatureLength = 64;

        /// <summary>
        /// A version 3 envelope carrying the domain given, so a test can
        /// make the domain as long as it likes.
        /// </summary>
        private static byte[] Envelope(string domain)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)OwidVersion.Version3);
                writer.Write(Encoding.ASCII.GetBytes(domain));
                writer.Write((byte)0);
                writer.Write((uint)1000);
                writer.Write((uint)Payload.Length);
                writer.Write(Payload);
                writer.Write(Signature);
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
        /// A domain of the given length built from labels of at most 63
        /// characters, so the text is a shape a real domain could take
        /// rather than one very long run of letters.
        /// </summary>
        private static string DomainOfLength(int length)
        {
            var text = new StringBuilder();
            var letter = 'a';
            while (text.Length < length)
            {
                if (text.Length > 0) { text.Append('.'); }
                var label = Math.Min(63, length - text.Length);
                text.Append(new string(letter, label));
                letter = letter == 'z' ? 'a' : (char)(letter + 1);
            }
            Assert.AreEqual(length, text.Length);
            return text.ToString();
        }

        /// <summary>
        /// A domain of exactly the maximum parses and comes back the same,
        /// so the bound does not cut a domain that is allowed.
        /// </summary>
        [TestMethod]
        public void DomainOfMaximumLength_Parses()
        {
            var domain = DomainOfLength(253);
            var owid = TestOwid.Parse(Envelope(domain));
            Assert.AreEqual(domain, owid.Domain);
            Assert.AreEqual(253, owid.Domain.Length);
            CollectionAssert.AreEqual(Payload, owid.Payload);
            CollectionAssert.AreEqual(Signature, owid.Signature);
        }

        /// <summary>
        /// One character more than the maximum is refused, even though the
        /// envelope is otherwise well formed and does carry a terminator.
        /// </summary>
        [TestMethod]
        public void DomainOverMaximumLength_IsRefused()
        {
            var bytes = Envelope(DomainOfLength(254));
            TestOwid.AssertRefused(bytes, OwidParseStatus.InvalidDomainEncoding);
        }

        /// <summary>
        /// A buffer with no zero byte in it at all after the version is
        /// refused, and refusing it costs the same whether the buffer is
        /// small or large. The parse is given four mebibytes of domain
        /// bytes with no terminator among them and has to stop after the
        /// maximum, so it allocates under 64 KiB. Before the bound the walk
        /// ran to the end of the buffer collecting every byte it passed,
        /// which cost about 20 MB of allocation for this one envelope.
        /// </summary>
        [TestMethod]
        public void DomainWithNoTerminator_IsRefusedWithBoundedWork()
        {
            var bytes = new byte[1 + (4 * 1024 * 1024)];
            bytes[0] = (byte)OwidVersion.Version3;
            for (var i = 1; i < bytes.Length; i++) { bytes[i] = (byte)'a'; }
            var before = GC.GetAllocatedBytesForCurrentThread();
            TestOwid.AssertRefused(bytes, OwidParseStatus.InvalidDomainEncoding);
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.IsTrue(
                allocated < 64 * 1024, $"allocated {allocated} bytes");
        }

        /// <summary>
        /// An ordinary domain is untouched by the bound, and the library's
        /// own output still parses, so the change is not retrospective on
        /// anything the library has already written.
        /// </summary>
        [TestMethod]
        public void LibraryOutput_Parses()
        {
            foreach (var domain in new[] { "51d.es", DomainOfLength(253) })
            {
                var original = new Model.Owid
                {
                    Domain = domain,
                    PayloadInternal = Payload,
                    SignatureInternal = Signature,
                };
                var parsed = TestOwid.Parse(original.AsByteArray());
                Assert.AreEqual(domain, parsed.Domain);
                CollectionAssert.AreEqual(Payload, parsed.Payload);
                CollectionAssert.AreEqual(Signature, parsed.Signature);
            }
        }

        /// <summary>
        /// A creator takes a domain of exactly the maximum, and the OWID it
        /// signs serialises, parses back to the same domain and still
        /// verifies, so the write bound refuses nothing the read accepts.
        /// </summary>
        [TestMethod]
        public void CreatorDomainOfMaximumLength_SignsAndParses()
        {
            var domain = DomainOfLength(253);
            using (var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var creator = new Creator(domain, crypto);
                var owid = creator.Create(Payload);
                Assert.AreEqual(domain, owid.Domain);
                var parsed = TestOwid.Parse(owid.AsByteArray());
                Assert.AreEqual(domain, parsed.Domain);
                Assert.AreEqual(253, parsed.Domain.Length);
                CollectionAssert.AreEqual(Payload, parsed.Payload);
                Assert.IsTrue(parsed.Verify(crypto));
            }
        }

        /// <summary>
        /// A creator domain one character over the maximum is refused where
        /// the caller gives it, with the maximum named in the message. The
        /// key is disposed before the creator is made, so the refusal has
        /// to arrive before the creator tries to sign with that key,
        /// otherwise the failure would be about the key instead.
        /// </summary>
        [TestMethod]
        public void CreatorDomainOverMaximumLength_IsRefusedBeforeSigning()
        {
            var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            crypto.Dispose();
            var refused = Assert.ThrowsExactly<ArgumentException>(
                () => new Creator(DomainOfLength(254), crypto));
            StringAssert.Contains(refused.Message, "253");
        }

        /// <summary>
        /// The same refusal for a creator made from configuration. The
        /// private key is empty, which the creator refuses on its own, so
        /// the domain message rather than the key message proves the domain
        /// is taken first.
        /// </summary>
        [TestMethod]
        public void ConfigurationDomainOverMaximumLength_IsRefused()
        {
            var configuration = new OwidConfiguration()
            {
                Domain = DomainOfLength(254),
                PrivateKey = string.Empty,
            };
            var refused = Assert.ThrowsExactly<ArgumentException>(
                () => new Creator(configuration));
            StringAssert.Contains(refused.Message, "253");
        }

        /// <summary>
        /// A domain set straight onto an OWID never passes through a
        /// creator, so serialising refuses it as well, and the bytes this
        /// library would refuse to parse are never produced.
        /// </summary>
        [TestMethod]
        public void SerialisedDomainOverMaximumLength_IsRefused()
        {
            var owid = new Model.Owid()
            {
                Domain = DomainOfLength(254),
                PayloadInternal = Payload,
                SignatureInternal = Signature,
            };
            var refused = Assert.ThrowsExactly<Exception>(
                () => owid.AsByteArray());
            StringAssert.Contains(refused.Message, "253");
        }

        /// <summary>
        /// Signing gathers the bytes of the OWID and of the others it is
        /// signed with before the key is used, so an other carrying a
        /// domain over the maximum is refused before the signature is
        /// computed. The creator's key is disposed once the creator holds
        /// it, so reaching the signature at all would fail about the key
        /// rather than about the domain.
        /// </summary>
        [TestMethod]
        public void SigningWithOverLongOtherDomain_IsRefusedBeforeSigning()
        {
            var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var creator = new Creator("51d.es", crypto);
            crypto.Dispose();
            var other = new Model.Owid()
            {
                Domain = DomainOfLength(254),
                PayloadInternal = Payload,
                SignatureInternal = Signature,
            };
            var refused = Assert.ThrowsExactly<Exception>(
                () => creator.Sign(
                    new Model.Owid() { PayloadInternal = Payload },
                    other));
            StringAssert.Contains(refused.Message, "253");
        }
    }
}
