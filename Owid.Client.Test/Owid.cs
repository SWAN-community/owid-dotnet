/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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
    [TestClass]
    public class Owid
    {
        private const string TestText = "Hello World";
        private const string TestDomain = "test.com";

        private string PublicPEM;
        private string PrivatePEM;

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
