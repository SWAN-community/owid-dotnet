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
    /// Cross language interoperability tests. The embedded fixtures were
    /// signed by the Rust and Go implementations on 2026-06-12 using
    /// throwaway ECDSA P-256 keys created only for these fixtures. The Go
    /// signer includes the signature alignment fix. At generation time the
    /// full matrix was verified, with each of the Go, .NET, JavaScript and
    /// Rust implementations verifying all fixtures and rejecting tampered
    /// copies. These tests prove that this implementation verifies OWIDs
    /// produced by the other implementations and reproduces their
    /// serialization byte for byte.
    /// </summary>
    [TestClass]
    public class OwidInteropTests
    {
        /// <summary>
        /// Expected text of the UTF-8 fixture payloads.
        /// </summary>
        private const string Utf8Text = "Zürich ❤ OWID £€";

        /// <summary>
        /// Public key used to sign the Rust fixtures.
        /// </summary>
        private const string RustPublicPem =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki\n" +
            "aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==\n" +
            "-----END PUBLIC KEY-----\n";

        /// <summary>
        /// Rust fixture with the ASCII payload "example".
        /// </summary>
        private const string RustSimple =
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyfDxby" +
            "kxurSxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/ErjSOMMQo" +
            "5CI=";

        /// <summary>
        /// Rust fixture with a UTF-8 payload containing non ASCII text.
        /// </summary>
        private const string RustUtf8 =
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDCo+KC" +
            "rDHenDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZUWDIobtJH" +
            "E5n9a81pTsn/Kvi74Azzx4s=";

        /// <summary>
        /// Public key used to sign the Go fixtures.
        /// </summary>
        private const string GoPublicPem =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n" +
            "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n" +
            "-----END PUBLIC KEY-----\n";

        /// <summary>
        /// Go fixture with the ASCII payload "example".
        /// </summary>
        private const string GoSimple =
            "A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMDfcAk" +
            "Rk8U4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4ojeSzNX56Qn";

        /// <summary>
        /// Go fixture with a UTF-8 payload containing non ASCII text.
        /// </summary>
        private const string GoUtf8 =
            "A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPigqzx" +
            "Y+4QgUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QCWZfkcKCKN" +
            "GSM8hYZEfYjJtViG+tA+";

        /// <summary>
        /// Test that the simple Rust fixture verifies with the Rust public
        /// key.
        /// </summary>
        [TestMethod]
        public async Task TestInteropRustSimpleVerifies()
        {
            await AssertVerifiesAsync(RustPublicPem, RustSimple);
        }

        /// <summary>
        /// Test that the UTF-8 Rust fixture verifies with the Rust public
        /// key.
        /// </summary>
        [TestMethod]
        public async Task TestInteropRustUtf8Verifies()
        {
            await AssertVerifiesAsync(RustPublicPem, RustUtf8);
        }

        /// <summary>
        /// Test that each Rust fixture fails verification after the final
        /// signature byte is flipped.
        /// </summary>
        [TestMethod]
        public async Task TestInteropRustTamperedSignatureFails()
        {
            await AssertTamperedFailsAsync(RustPublicPem, RustSimple);
            await AssertTamperedFailsAsync(RustPublicPem, RustUtf8);
        }

        /// <summary>
        /// Test that the UTF-8 Rust fixture payload decodes to the expected
        /// text.
        /// </summary>
        [TestMethod]
        public void TestInteropRustUtf8PayloadText()
        {
            AssertUtf8Payload(RustUtf8);
        }

        /// <summary>
        /// Test that each Rust fixture re-serializes to the original Base64
        /// string exactly.
        /// </summary>
        [TestMethod]
        public void TestInteropRustSerializationRoundtrip()
        {
            AssertRoundtrip(RustSimple, RustUtf8);
        }

        /// <summary>
        /// Test that the simple Go fixture verifies with the Go public key.
        /// </summary>
        [TestMethod]
        public async Task TestInteropGoSimpleVerifies()
        {
            await AssertVerifiesAsync(GoPublicPem, GoSimple);
        }

        /// <summary>
        /// Test that the UTF-8 Go fixture verifies with the Go public key.
        /// </summary>
        [TestMethod]
        public async Task TestInteropGoUtf8Verifies()
        {
            await AssertVerifiesAsync(GoPublicPem, GoUtf8);
        }

        /// <summary>
        /// Test that each Go fixture fails verification after the final
        /// signature byte is flipped.
        /// </summary>
        [TestMethod]
        public async Task TestInteropGoTamperedSignatureFails()
        {
            await AssertTamperedFailsAsync(GoPublicPem, GoSimple);
            await AssertTamperedFailsAsync(GoPublicPem, GoUtf8);
        }

        /// <summary>
        /// Test that the UTF-8 Go fixture payload decodes to the expected
        /// text.
        /// </summary>
        [TestMethod]
        public void TestInteropGoUtf8PayloadText()
        {
            AssertUtf8Payload(GoUtf8);
        }

        /// <summary>
        /// Test that each Go fixture re-serializes to the original Base64
        /// string exactly.
        /// </summary>
        [TestMethod]
        public void TestInteropGoSerializationRoundtrip()
        {
            AssertRoundtrip(GoSimple, GoUtf8);
        }

        /// <summary>
        /// Assert that the fixture verifies with the public key.
        /// </summary>
        private static async Task AssertVerifiesAsync(
            string publicPem,
            string base64)
        {
            var owid = TestOwid.Parse(base64);
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(publicPem);
                Assert.IsTrue(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Assert that the fixture fails verification after the final byte
        /// of its serialized form, a signature byte, is XORed with 0xFF.
        /// </summary>
        private static async Task AssertTamperedFailsAsync(
            string publicPem,
            string base64)
        {
            // Flip the final byte which is part of the signature.
            var bytes = Convert.FromBase64String(base64);
            bytes[bytes.Length - 1] = (byte)(bytes[bytes.Length - 1] ^ 0xFF);

            var owid = TestOwid.Parse(bytes);
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(publicPem);
                Assert.IsFalse(await owid.VerifyAsync(crypto));
            }
        }

        /// <summary>
        /// Assert that the fixture payload decodes to the expected UTF-8
        /// text. PayloadAsString is ASCII only by documented design so the
        /// payload bytes are decoded with UTF-8 instead.
        /// </summary>
        private static void AssertUtf8Payload(string base64)
        {
            var owid = TestOwid.Parse(base64);
            Assert.AreEqual(Utf8Text, Encoding.UTF8.GetString(owid.Payload));
        }

        /// <summary>
        /// Assert that each fixture re-serializes to the original Base64
        /// string exactly.
        /// </summary>
        private static void AssertRoundtrip(params string[] fixtures)
        {
            foreach (var base64 in fixtures)
            {
                var owid = TestOwid.Parse(base64);
                Assert.AreEqual(base64, owid.AsBase64());
            }
        }
    }
}
