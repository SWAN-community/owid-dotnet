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
        /// Test the synchronous Verify accepts a genuine OWID and rejects a
        /// tampered one, matching the asynchronous behaviour.
        /// </summary>
        [TestMethod]
        public void TestSynchronousVerify()
        {
            var owid = CreateOwid();

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(owid.Verify(crypto));

                owid.Signature[0] = (byte)(owid.Signature[0] ^ 0xFF);
                Assert.IsFalse(owid.Verify(crypto));
            }
        }

        /// <summary>
        /// Test GetByteCount matches the serialized length exactly, so the
        /// presized serialization buffers can never be wrong silently.
        /// </summary>
        [TestMethod]
        public void TestGetByteCountMatchesSerializedLength()
        {
            var owid = CreateOwid();
            Assert.AreEqual(owid.GetByteCount(), owid.AsByteArray().Length);

            // And with an empty payload.
            var empty = new Model.Owid();
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                new Creator(TestDomain, crypto).Sign(empty);
            }
            Assert.AreEqual(empty.GetByteCount(), empty.AsByteArray().Length);
        }

        /// <summary>
        /// Test GetSignedBytes returns exactly the serialized bytes minus
        /// the signature, and that verifying those bytes directly agrees
        /// with Verify.
        /// </summary>
        [TestMethod]
        public void TestGetSignedBytesMatchesSerializedPrefix()
        {
            var owid = CreateOwid();
            var whole = owid.AsByteArray();
            var signed = owid.GetSignedBytes();

            Assert.AreEqual(whole.Length - 64, signed.Length);
            for (var i = 0; i < signed.Length; i++)
            {
                Assert.AreEqual(whole[i], signed[i], $"byte {i} differs");
            }

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(crypto.VerifyData(
                    signed, owid.Signature, HashAlgorithmName.SHA256));
            }
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
    }
}
