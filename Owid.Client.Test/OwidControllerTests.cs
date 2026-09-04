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

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Controllers;
using Owid.Client.Model;
using Owid.Client.Model.Configuration;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

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
        public async Task TestGetPublicKeyReturnsConfiguredKey()
        {
            using (var controller = new OwidController(Configuration!))
            {
                Assert.AreEqual(
                    Configuration!.PublicKey,
                    (await controller.GetPublicKey()).Value);
            }
        }

        /// <summary>
        /// Test that the creator endpoint returns the configured domain. The
        /// current implementation returns the domain string only rather than
        /// a JSON document.
        /// </summary>
        [TestMethod]
        public async Task TestGetCreatorReturnsConfiguredDomain()
        {
            using (var controller = new OwidController(Configuration!))
            {
                var creator = (await controller.GetCreator()).Value;
                Assert.AreEqual(Configuration!.Domain, creator!.Domain);
                Assert.AreEqual(Configuration!.PublicKey, creator!.PublicKeySPKI);
            }
        }

        /// <summary>
        /// A supplied date selects the creator's key through the store, so the
        /// creator and public-key endpoints agree.
        /// </summary>
        [TestMethod]
        public async Task TestGetCreatorWithDateUsesStore()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "old" },
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 15, 0, 0, 0, DateTimeKind.Utc), PublicKey = "new" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var epoch = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var minutes = (uint)(
                    new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc) - epoch)
                    .TotalMinutes;
                var creator = (await controller.GetCreator(minutes)).Value;
                Assert.AreEqual("old", creator!.PublicKeySPKI);
            }
        }

        /// <summary>
        /// A date before any known key produces a 404 on the creator endpoint.
        /// </summary>
        [TestMethod]
        public async Task TestGetCreatorDateBeforeOldestReturns404()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var result = await controller.GetCreator(1440);
                Assert.IsInstanceOfType(result.Result, typeof(NotFoundResult));
            }
        }

        /// <summary>
        /// A supplied date is resolved through the injected key store.
        /// </summary>
        [TestMethod]
        public async Task TestGetPublicKeyWithDateUsesStore()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "old" },
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 15, 0, 0, 0, DateTimeKind.Utc), PublicKey = "new" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var epoch = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var minutes = (uint)(
                    new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc) - epoch)
                    .TotalMinutes;
                Assert.AreEqual(
                    "old", (await controller.GetPublicKey(minutes)).Value);
            }
        }

        /// <summary>
        /// A date before any known key produces a 404.
        /// </summary>
        [TestMethod]
        public async Task TestGetPublicKeyDateBeforeOldestReturns404()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                // 1440 minutes after the epoch is 2020-01-02, before the key.
                var result = await controller.GetPublicKey(1440);
                Assert.IsInstanceOfType(result.Result, typeof(NotFoundResult));
            }
        }

        /// <summary>
        /// A denying authorizer's result is returned from both endpoints.
        /// </summary>
        [TestMethod]
        public async Task TestAuthorizerDeniedResultIsReturned()
        {
            var authorizer = new StubAuthorizer(new UnauthorizedResult());
            using (var controller = new OwidController(
                Configuration!, null, authorizer))
            {
                controller.ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext()
                };
                Assert.IsInstanceOfType(
                    (await controller.GetPublicKey()).Result,
                    typeof(UnauthorizedResult));
                Assert.IsInstanceOfType(
                    (await controller.GetCreator()).Result,
                    typeof(UnauthorizedResult));
            }
        }

        /// <summary>
        /// An authorizer that returns null lets the request through.
        /// </summary>
        [TestMethod]
        public async Task TestAuthorizerAllowingRequestReturnsValues()
        {
            var authorizer = new StubAuthorizer(null);
            using (var controller = new OwidController(
                Configuration!, null, authorizer))
            {
                controller.ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext()
                };
                Assert.AreEqual(
                    Configuration!.PublicKey,
                    (await controller.GetPublicKey()).Value);
                Assert.AreEqual(
                    Configuration!.Domain,
                    (await controller.GetCreator()).Value!.Domain);
            }
        }

        private sealed class StubAuthorizer : IOwidAuthorizer
        {
            private readonly ActionResult? _result;

            public StubAuthorizer(ActionResult? result)
            {
                _result = result;
            }

            public Task<ActionResult?> AuthorizeAsync(HttpRequest request) =>
                Task.FromResult(_result);
        }
    }
}
