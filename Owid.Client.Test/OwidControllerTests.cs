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
                var answer = (await controller.GetPublicKey()).Value!;
                Assert.AreEqual(Configuration!.PublicKey, answer.PublicKeySPKI);
                Assert.IsNull(answer.ValidFrom, "the configured key has no schedule");
                Assert.IsNull(answer.ValidTo);
            }
        }

        /// <summary>
        /// The public key of a newly made key pair, in PEM form, for a store
        /// whose answer has to pass the checks a creator applies before
        /// sending it.
        /// </summary>
        private static string FreshPem()
        {
            using var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new String(PemEncoding.Write(
                "PUBLIC KEY", crypto.ExportSubjectPublicKeyInfo()));
        }

        /// <summary>
        /// A supplied date is resolved through the injected key store.
        /// </summary>
        [TestMethod]
        public async Task TestGetPublicKeyWithDateUsesStore()
        {
            var oldKey = FreshPem();
            var newKey = FreshPem();
            var oldStart = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc);
            var newStart = new DateTime(2026, 3, 15, 0, 0, 0, DateTimeKind.Utc);
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = oldStart, PublicKey = oldKey },
                new DatedPublicKey { StartsAt = newStart, PublicKey = newKey },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var epoch = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var minutes = (uint)(
                    new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc) - epoch)
                    .TotalMinutes;
                var answer = (await controller.GetPublicKey(minutes)).Value!;
                Assert.AreEqual(oldKey, answer.PublicKeySPKI);
                Assert.AreEqual(oldStart, answer.ValidFrom!.Value,
                    "the answer states when the old key came into force");
                Assert.AreEqual(newStart, answer.ValidTo!.Value,
                    "and when the new key takes over");

                minutes = (uint)(
                    new DateTime(2026, 3, 20, 0, 0, 0, DateTimeKind.Utc) - epoch)
                    .TotalMinutes;
                answer = (await controller.GetPublicKey(minutes)).Value!;
                Assert.AreEqual(newKey, answer.PublicKeySPKI);
                Assert.AreEqual(newStart, answer.ValidFrom!.Value);
                Assert.IsNull(answer.ValidTo, "the last key of the schedule has no end");
            }
        }

        /// <summary>
        /// A store holding something that is not a public key, or a schedule
        /// that contradicts itself, is a server error rather than an answer
        /// a client would then have to refuse.
        /// </summary>
        [TestMethod]
        public async Task TestGetPublicKeyRefusesAnAnswerAClientWouldRefuse()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey { StartsAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "not a key" },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                var result = (await controller.GetPublicKey()).Result as ObjectResult;
                Assert.IsNotNull(result, "a key that cannot be read is answered with a status");
                Assert.AreEqual(StatusCodes.Status500InternalServerError, result!.StatusCode);
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
        /// An undated request when no key has started yet is a 404, never a
        /// success with no key in it. A schedule is published ahead of time,
        /// so this is an ordinary state for a creator whose first period has
        /// not begun.
        /// </summary>
        [TestMethod]
        public async Task TestNothingInForceYetReturns404()
        {
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey
                {
                    StartsAt = DateTime.UtcNow.AddDays(7),
                    PublicKey = "not-started",
                },
            });
            using (var controller = new OwidController(Configuration!, store))
            {
                Assert.IsInstanceOfType(
                    (await controller.GetPublicKey()).Result,
                    typeof(NotFoundResult));
            }
        }

        /// <summary>
        /// A date later than the moment of the request is read as that
        /// moment, so a key whose period has not started is never handed
        /// out. This is what the 51Degrees cloud does with the same request.
        /// </summary>
        [TestMethod]
        public async Task TestFutureDateIsReadAsNow()
        {
            var now = DateTime.UtcNow;
            var inForce = FreshPem();
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey
                {
                    StartsAt = now.AddDays(-7),
                    PublicKey = inForce,
                },
                new DatedPublicKey
                {
                    StartsAt = now.AddDays(7),
                    PublicKey = FreshPem(),
                },
            });
            var epoch = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var nextMonth = (uint)(now.AddDays(30) - epoch).TotalMinutes;
            using (var controller = new OwidController(Configuration!, store))
            {
                Assert.AreEqual(
                    inForce,
                    (await controller.GetPublicKey(nextMonth)).Value!.PublicKeySPKI);
                // The largest value the parameter can carry is later than
                // now as well, so it takes the same answer.
                Assert.AreEqual(
                    inForce,
                    (await controller.GetPublicKey(uint.MaxValue)).Value!.PublicKeySPKI);
            }
        }

        /// <summary>
        /// A denying authorizer's result is returned from the end point.
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
            }
        }

        /// <summary>
        /// An authorizer that returns null lets the request through.
        /// </summary>
        [TestMethod]
        public async Task TestAuthorizerAllowingRequestReturnsTheKey()
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
                    (await controller.GetPublicKey()).Value!.PublicKeySPKI);
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
