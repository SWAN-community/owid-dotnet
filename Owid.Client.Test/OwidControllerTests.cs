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

using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Controllers;
using Owid.Client.Model;
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
                    controller.GetPublicKey().Value);
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

        /// <summary>
        /// A supplied date is resolved through the injected key store.
        /// </summary>
        [TestMethod]
        public void TestGetPublicKeyWithDateUsesStore()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { Created = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "old" },
                new DatedPublicKey { Created = new DateTime(2026, 3, 15, 0, 0, 0, DateTimeKind.Utc), PublicKey = "new" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var epoch = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var minutes = (uint)(
                    new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc) - epoch)
                    .TotalMinutes;
                Assert.AreEqual("old", controller.GetPublicKey(minutes).Value);
            }
        }

        /// <summary>
        /// A date before any known key produces a 404.
        /// </summary>
        [TestMethod]
        public void TestGetPublicKeyDateBeforeOldestReturns404()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { Created = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                // 1440 minutes after the epoch is 2020-01-02, before the key.
                var result = controller.GetPublicKey(1440);
                Assert.IsInstanceOfType(result.Result, typeof(NotFoundResult));
            }
        }
    }
}
