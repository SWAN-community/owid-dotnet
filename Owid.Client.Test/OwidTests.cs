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
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Owid.Client.Test
{
    /// <summary>
    /// Tests for <see cref="Owid"/> and <see cref="Creator"/>.
    /// </summary>
    [TestClass]
    public class OwidTests
    {
        private const string TestText = "Hello World";
        private const string TestDomain = "test.com";

        private string? PublicPEM;
        private string? PrivatePEM;

        /// <summary>
        /// Initialize the test.
        /// </summary>
        [TestInitialize]
        public void TestInitialize()
        {
            using (var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = crypto.ExportParameters(true);
                var pubKeyBytes = crypto.ExportSubjectPublicKeyInfo();
                var privKeyBytes = crypto.ExportPkcs8PrivateKey();
                PublicPEM = new String(PemEncoding.Write("PUBLIC KEY", pubKeyBytes));
                PrivatePEM = new String(PemEncoding.Write("PRIVATE KEY", privKeyBytes));
            }
            using (var pub = ECDsa.Create())
            {
                pub.ImportFromPem(PublicPEM);
            }
            using (var priv = ECDsa.Create())
            {
                priv.ImportFromPem(PrivatePEM);
            }
        }

        /// <summary>
        /// Test <see cref="Owid"/> creation.
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public async Task TestCreate()
        {
            // Create a new OWID.
            var original = CreateOwid();
            Assert.IsNotNull(original);

            // Verify the OWID with the public key.
            using (var rsa = ECDsa.Create())
            {
                rsa.ImportFromPem(PublicPEM);
                Assert.IsTrue(await original.VerifyAsync(rsa));
            }

            // Turn the OWID into a base 64 string.
            var owidString = original.AsBase64();

            // Create a new OWID from the base 64 string.
            var copy = new Model.Owid(owidString);

            // Verify the copy OWID with the public key.
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await copy.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that verification fails with an invalid signature.
        /// </summary>
        [TestMethod]
        public async Task TestVerificationFailsWithInvalidSignature()
        {
            var owid = CreateOwid();
            
            // Tamper with the signature
            owid.Signature[0] = (byte)(owid.Signature[0] ^ 0xFF);

            // Verification should fail with corrupted signature
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsFalse(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that verification fails with wrong public key.
        /// </summary>
        [TestMethod]
        public async Task TestVerificationFailsWithWrongPublicKey()
        {
            var owid = CreateOwid();

            // Create a different key pair for verification
            using (var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                Assert.IsFalse(await owid.VerifyAsync(wrongKey));
            }
        }

        /// <summary>
        /// Test OWID creation with empty payload.
        /// </summary>
        [TestMethod]
        public async Task TestCreateWithEmptyPayload()
        {
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Date = DateTime.UtcNow;
                owid.Payload = Array.Empty<byte>();
                creator.Sign(owid);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test OWID creation with large payload.
        /// </summary>
        [TestMethod]
        public async Task TestCreateWithLargePayload()
        {
            var owid = new Model.Owid();
            var largePayload = new byte[10000];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(largePayload);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Date = DateTime.UtcNow;
                owid.Payload = largePayload;
                creator.Sign(owid);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test Creator.Sign with string payload.
        /// </summary>
        [TestMethod]
        public async Task TestCreatorSignWithStringPayload()
        {
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                
                var owid = creator.Sign(TestText);
                Assert.AreEqual(TestText, owid.PayloadAsString);

                using (var verifyKey = ECDsa.Create())
                {
                    verifyKey.ImportFromPem(PublicPEM);
                    Assert.IsTrue(await owid.VerifyAsync(verifyKey));
                }
            }
        }

        /// <summary>
        /// Test Creator.Sign with byte payload.
        /// </summary>
        [TestMethod]
        public async Task TestCreatorSignWithBytePayload()
        {
            var payload = Encoding.UTF8.GetBytes(TestText);
            
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                
                var owid = creator.Sign(payload);
                CollectionAssert.AreEqual(payload, owid.Payload);

                using (var verifyKey = ECDsa.Create())
                {
                    verifyKey.ImportFromPem(PublicPEM);
                    Assert.IsTrue(await owid.VerifyAsync(verifyKey));
                }
            }
        }

        /// <summary>
        /// Test that domain is correctly set by Creator.
        /// </summary>
        [TestMethod]
        public void TestCreatorSetsDomain()
        {
            var owid = new Model.Owid();
            
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.ASCII.GetBytes(TestText);
                creator.Sign(owid);
            }

            Assert.AreEqual(TestDomain, owid.Domain);
        }

        /// <summary>
        /// Test OWID serialization and deserialization roundtrip.
        /// </summary>
        [TestMethod]
        public async Task TestSerializationRoundtrip()
        {
            var original = CreateOwid();

            // Multiple encode/decode cycles
            var encoded1 = original.AsBase64();
            var decoded1 = new Model.Owid(encoded1);
            var encoded2 = decoded1.AsBase64();
            var decoded2 = new Model.Owid(encoded2);

            // All should verify successfully
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await original.VerifyAsync(crypto));
                Assert.IsTrue(await decoded1.VerifyAsync(crypto));
                Assert.IsTrue(await decoded2.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that invalid Base64 throws on deserialization.
        /// </summary>
        [TestMethod]
        public void TestInvalidBase64Throws()
        {
            var invalidBase64 = "This is not valid Base64!@#$";
            Assert.ThrowsExactly<FormatException>(() => new Model.Owid(invalidBase64));
        }

        /// <summary>
        /// Test batch OWID creation and verification.
        /// </summary>
        [TestMethod]
        public async Task TestBatchSigningAndVerification()
        {
            const int batchSize = 10;
            var owids = new Model.Owid[batchSize];

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);

                for (int i = 0; i < batchSize; i++)
                {
                    var payload = Encoding.ASCII.GetBytes($"Payload {i}");
                    owids[i] = creator.Sign(payload);
                }
            }

            // Verify all OWIDs
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                for (int i = 0; i < batchSize; i++)
                {
                    Assert.IsTrue(await owids[i].VerifyAsync(crypto));
                }
            }
        }

        /// <summary>
        /// Test OWID with modified domain fails verification.
        /// </summary>
        [TestMethod]
        public async Task TestModifiedDomainFailsVerification()
        {
            var owid = CreateOwid();
            var originalDomain = owid.Domain;
            
            // Modify the domain
            owid.Domain = "different.com";

            // Verification should fail
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsFalse(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that an OWID signed with others verifies when the same others
        /// are provided to verification.
        /// </summary>
        [TestMethod]
        public async Task TestSignWithOthersVerifiesWithSameOthers()
        {
            var others = CreateOthers(2);
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.ASCII.GetBytes(TestText);
                creator.Sign(owid, others);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await owid.VerifyAsync(crypto, others));
            }
        }

        /// <summary>
        /// Test that an OWID signed with others fails verification when the
        /// others are not provided.
        /// </summary>
        [TestMethod]
        public async Task TestSignWithOthersFailsWithoutOthers()
        {
            var others = CreateOthers(2);
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.ASCII.GetBytes(TestText);
                creator.Sign(owid, others);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsFalse(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that an OWID signed with others fails verification when
        /// different others are provided.
        /// </summary>
        [TestMethod]
        public async Task TestSignWithOthersFailsWithDifferentOthers()
        {
            var others = CreateOthers(2);
            var different = CreateOthers(2);
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.ASCII.GetBytes(TestText);
                creator.Sign(owid, others);
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsFalse(await owid.VerifyAsync(crypto, different));
            }
        }

        /// <summary>
        /// Test that a payload modified after signing fails verification.
        /// </summary>
        [TestMethod]
        public async Task TestModifiedPayloadFailsVerification()
        {
            var owid = CreateOwid();

            // Tamper with the payload after signing.
            owid.Payload[0] = (byte)(owid.Payload[0] ^ 0xFF);

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsFalse(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that converting to a byte array and back preserves all the
        /// fields and the result still verifies.
        /// </summary>
        [TestMethod]
        public async Task TestByteArrayRoundtrip()
        {
            var original = CreateOwid();
            var bytes = original.AsByteArray();
            var copy = new Model.Owid(bytes);

            Assert.AreEqual(original.Version, copy.Version);
            Assert.AreEqual(original.Domain, copy.Domain);

            // Dates are stored to the minute so compare after flooring the
            // original to the minute.
            var expectedDate = FloorToMinute(original.Date);
            Assert.AreEqual(expectedDate, copy.Date);

            CollectionAssert.AreEqual(original.Payload, copy.Payload);
            CollectionAssert.AreEqual(original.Signature, copy.Signature);

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await copy.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that a truncated Base64 OWID produces a clean exception. A
        /// truncation that removes part of the signature results in the
        /// signature length check throwing. A truncation that cuts into the
        /// header results in an end of stream exception when reading.
        /// </summary>
        [TestMethod]
        public void TestTruncatedBase64Throws()
        {
            var base64 = CreateOwid().AsBase64();

            // Truncate to half the length rounded down to a multiple of four
            // characters so the Base64 itself remains decodable. The missing
            // bytes are detected when the signature is read.
            var half = base64.Substring(0, base64.Length / 2 / 4 * 4);
            Assert.ThrowsExactly<Exception>(() => new Model.Owid(half));

            // Truncate to just the first eight characters which cuts the
            // buffer inside the domain producing an end of stream exception.
            var head = base64.Substring(0, 8);
            Assert.ThrowsExactly<EndOfStreamException>(
                () => new Model.Owid(head));
        }

        /// <summary>
        /// Test that corrupting any single byte of a serialized OWID causes
        /// either a parsing exception or a verification failure. Mirrors the
        /// corrupt replace test in the Go implementation.
        /// </summary>
        [TestMethod]
        public async Task TestCorruptAnyByteFailsVerificationOrThrows()
        {
            var bytes = CreateOwid().AsByteArray();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                for (var i = 0; i < bytes.Length; i++)
                {
                    var corrupt = (byte[])bytes.Clone();
                    corrupt[i] = (byte)(corrupt[i] ^ 0xFF);
                    var verified = false;
                    try
                    {
                        var owid = new Model.Owid(corrupt);
                        verified = await owid.VerifyAsync(crypto);
                    }
                    catch (Exception)
                    {
                        // A parsing exception is an acceptable outcome for a
                        // corrupt buffer.
                        continue;
                    }
                    Assert.IsFalse(
                        verified,
                        $"Corrupt byte at position '{i}' must not verify");
                }
            }
        }

        /// <summary>
        /// Test a payload containing non ASCII text. The payload bytes are
        /// preserved exactly through serialization so a UTF-8 payload can be
        /// recovered with UTF-8 decoding. PayloadAsString uses ASCII so it
        /// does not preserve non ASCII characters. This documents the current
        /// behavior which differs from the Go and JavaScript implementations
        /// where strings are handled as UTF-8.
        /// </summary>
        [TestMethod]
        public async Task TestNonAsciiPayloadRoundtrip()
        {
            const string text = "héllo wörld €100";
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.UTF8.GetBytes(text);
                creator.Sign(owid);
            }

            var copy = new Model.Owid(owid.AsBase64());

            // The payload bytes are preserved exactly.
            CollectionAssert.AreEqual(owid.Payload, copy.Payload);
            Assert.AreEqual(text, Encoding.UTF8.GetString(copy.Payload));

            // PayloadAsString uses ASCII and replaces non ASCII characters.
            Assert.AreNotEqual(text, copy.PayloadAsString);

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await copy.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Test that a configuration with a malformed PEM private key throws
        /// a clean exception when used to create a <see cref="Creator"/>.
        /// </summary>
        [TestMethod]
        public void TestCreatorWithInvalidPrivateKeyThrows()
        {
            var configuration = new Model.Configuration.OwidConfiguration
            {
                Domain = TestDomain,
                PrivateKey = "this is not a PEM private key"
            };
            Assert.Throws<ArgumentException>(
                () => new Creator(configuration));
        }

        /// <summary>
        /// Test that a PEM private key with a valid header but corrupt
        /// content throws a clean exception.
        /// </summary>
        [TestMethod]
        public void TestCreatorWithCorruptPrivateKeyThrows()
        {
            var configuration = new Model.Configuration.OwidConfiguration
            {
                Domain = TestDomain,
                PrivateKey =
                    "-----BEGIN PRIVATE KEY-----\n" +
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
                    "-----END PRIVATE KEY-----"
            };
            Assert.Throws<Exception>(() => new Creator(configuration));
        }

        /// <summary>
        /// Test that constructing a <see cref="Creator"/> with an empty or
        /// whitespace private key PEM throws an explicit
        /// <see cref="ArgumentException"/> rather than the opaque exception
        /// thrown by ImportFromPem. Mirrors the empty key PEM guard added
        /// across the OWID implementations.
        /// </summary>
        [TestMethod]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow("\t\n")]
        public void TestCreatorWithEmptyPrivateKeyThrows(string privateKey)
        {
            var configuration = new Model.Configuration.OwidConfiguration
            {
                Domain = TestDomain,
                PrivateKey = privateKey
            };
            var exception = Assert.Throws<ArgumentException>(
                () => new Creator(configuration));
            Assert.AreEqual("private key PEM is empty", exception.Message);
        }

        /// <summary>
        /// Test that the empty public key PEM guard used on the verify path
        /// rejects an empty or whitespace PEM with an explicit
        /// <see cref="ArgumentException"/>. The verify path fetches the public
        /// key over HTTP so the guard condition is exercised here directly to
        /// match the behavior in
        /// <see cref="CryptoExtensions"/>.
        /// </summary>
        [TestMethod]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow("\t\n")]
        public void TestEmptyPublicKeyPemIsRejected(string publicKeyPem)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                if (string.IsNullOrWhiteSpace(publicKeyPem))
                {
                    throw new ArgumentException("public key PEM is empty");
                }
                using var key = ECDsa.Create();
                key.ImportFromPem(publicKeyPem);
            });
            Assert.AreEqual("public key PEM is empty", exception.Message);
        }

        private Model.Owid CreateOwid()
        {
            var owid = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Date = DateTime.UtcNow;
                owid.Payload = ASCIIEncoding.ASCII.GetBytes(TestText);
                creator.Sign(owid);
            }
            return owid;
        }

        private Model.Owid[] CreateOthers(int count)
        {
            var others = new Model.Owid[count];
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                for (var i = 0; i < count; i++)
                {
                    others[i] = creator.Sign($"Other {Guid.NewGuid()}");
                }
            }
            return others;
        }

        internal static DateTime FloorToMinute(DateTime date)
        {
            var baseDate = new DateTime(
                2020, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            return baseDate.AddMinutes((uint)(date - baseDate).TotalMinutes);
        }
    }
}
