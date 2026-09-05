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
using Owid.Client.Model;
using Owid.Client.Model.Configuration;
using System;
using System.Threading.Tasks;

namespace Owid.Client.Controllers
{
    /// <summary>
    /// API controller to enable verification
    /// of <see cref="Owid"/> signatures.
    /// </summary>
    [Route("[controller]/api/v1")]
    [Route("[controller]/api/v2")]
    [Route("[controller]/api/v3")]
    [ApiController]
    public class OwidController : Controller
    {
        private readonly OwidConfiguration _owidConfiguration;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly IOwidAuthorizer? _authorizer;

        /// <summary>
        /// The moment the OWID date encoding counts minutes from.
        /// </summary>
        private static readonly DateTime OwidBaseDate =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="owidConfiguration">The OWID creator configuration.</param>
        /// <param name="publicKeyStore">
        /// Optional source of signing public keys. When not supplied the single
        /// key from <paramref name="owidConfiguration"/> is used.
        /// </param>
        /// <param name="authorizer">
        /// Optional check applied to every request. When not supplied the
        /// endpoints are open, per the OWID specification's default.
        /// </param>
        public OwidController(
            OwidConfiguration owidConfiguration,
            IPublicKeyStore? publicKeyStore = null,
            IOwidAuthorizer? authorizer = null)
        {
            _owidConfiguration = owidConfiguration;
            _publicKeyStore = publicKeyStore
                ?? new ConfigurationPublicKeyStore(owidConfiguration);
            _authorizer = authorizer;
        }

        /// <summary>
        /// The requested date, or the moment of the request where the date is
        /// later than that. A schedule is published ahead of time, so a date
        /// in the future names a key that has not started and has signed
        /// nothing, and the key in force now is the only honest answer for
        /// it. A count past the range of <see cref="DateTime"/> is later than
        /// now as well, so it takes the same answer rather than an error.
        /// </summary>
        private static uint? ClampToNow(uint? date)
        {
            if (date == null)
            {
                return null;
            }
            var nowMinutes = (DateTime.UtcNow - OwidBaseDate).TotalMinutes;
            var now = nowMinutes >= uint.MaxValue
                ? uint.MaxValue
                : (uint)nowMinutes;
            return Math.Min(date.Value, now);
        }

        /// <summary>
        /// Returns the public key for the OWID creator. With a date, returns
        /// the key in force at that date; without one, the key in force now.
        /// A date later than the moment of the request is read as that
        /// moment.
        /// </summary>
        /// <param name="date">
        /// Optional date as minutes since 2020-01-01 UTC (the OWID date
        /// encoding).
        /// </param>
        /// <returns>
        /// The public key, or 404 when no key was active at the requested date.
        /// </returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [HttpGet("public-key")]
        [HttpPost("public-key")]
        public async Task<ActionResult<string?>> GetPublicKey(uint? date = null)
        {
            var denied = await AuthorizeAsync();
            if (denied != null)
            {
                return denied;
            }
            var key = _publicKeyStore.GetPublicKey(ClampToNow(date));
            if (key == null)
            {
                // Nothing is in force at the requested moment, which for an
                // undated request means no key has started yet. Answered as
                // not found rather than as an empty success, so a verifier
                // never reads a missing key as a key.
                return NotFound();
            }
            return key;
        }


        /// <summary>
        /// Returns the creator domain and signing public key. With a date,
        /// returns the key in force at that date; without one, the key in
        /// force now, and a date later than the moment of the request is read
        /// as that moment. This matches the public-key end point so the two
        /// agree.
        /// </summary>
        /// <param name="date">
        /// Optional date as minutes since 2020-01-01 UTC (the OWID date
        /// encoding).
        /// </param>
        /// <returns>
        /// The creator info, or 404 when no key was active at the requested
        /// date.
        /// </returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [HttpGet("creator")]
        [HttpPost("creator")]
        public async Task<ActionResult<CreatorResponse>> GetCreator(
            uint? date = null)
        {
            var denied = await AuthorizeAsync();
            if (denied != null)
            {
                return denied;
            }
            var key = _publicKeyStore.GetPublicKey(ClampToNow(date));
            if (key == null)
            {
                return NotFound();
            }
            return new CreatorResponse
            {
                Domain = _owidConfiguration.Domain,
                PublicKeySPKI = key,
            };
        }

        private Task<ActionResult?> AuthorizeAsync() =>
            _authorizer == null
                ? Task.FromResult<ActionResult?>(null)
                : _authorizer.AuthorizeAsync(Request);
    }
}
