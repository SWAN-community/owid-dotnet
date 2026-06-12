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
using Owid.Client.Controllers;
using Owid.Client.Model.Configuration;
using System;
using System.Security.Cryptography;

namespace Owid.Client.Test
{
    /// <summary>
    /// Tests for <see cref="OwidController"/> using a directly constructed
    /// instance. No test server is required as the endpoints return values
    /// straight from the configuration.
    /// </summary>
    [TestClass]
    public class OwidControllerTests
    {
        private const string TestDomain = "test.com";

        private OwidConfiguration? Configuration;

        /// <summary>
        /// Initialize the test.
        /// </summary>
        [TestInitialize]
        public void TestInitialize()
        {
            using (var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                Configuration = new OwidConfiguration
                {
                    Domain = TestDomain,
                    PublicKey = new String(PemEncoding.Write(
                        "PUBLIC KEY",
                        crypto.ExportSubjectPublicKeyInfo())),
                    PrivateKey = new String(PemEncoding.Write(
                        "PRIVATE KEY",
                        crypto.ExportPkcs8PrivateKey()))
                };
            }
        }

        /// <summary>
        /// Test that the public key endpoint returns the configured public
        /// key.
        /// </summary>
        [TestMethod]
        public void TestGetPublicKeyReturnsConfiguredKey()
        {
            using (var controller = new OwidController(Configuration!))
            {
                Assert.AreEqual(
                    Configuration!.PublicKey,
                    controller.GetPublicKey());
            }
        }

        /// <summary>
        /// Test that the creator endpoint returns the configured domain. The
        /// current implementation returns the domain string only rather than
        /// a JSON document.
        /// </summary>
        [TestMethod]
        public void TestGetCreatorReturnsConfiguredDomain()
        {
            using (var controller = new OwidController(Configuration!))
            {
                Assert.AreEqual(
                    Configuration!.Domain,
                    controller.GetCreator());
            }
        }
    }
}
