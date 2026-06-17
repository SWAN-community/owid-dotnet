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

namespace Owid.Client.Controllers
{
    /// <summary>
    /// API controller to enable verification
    /// of <see cref="Owid"/> signatures.
    /// </summary>
    [Route("[controller]/api/v1")]
    [Route("[controller]/api/v2")]
    [ApiController]
    public class OwidController : Controller
    {
        private readonly OwidConfiguration _owidConfiguration;
        private readonly IPublicKeyStore _publicKeyStore;

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="owidConfiguration">The OWID creator configuration.</param>
        /// <param name="publicKeyStore">
        /// Optional source of signing public keys. When not supplied the single
        /// key from <paramref name="owidConfiguration"/> is used.
        /// </param>
        public OwidController(
            OwidConfiguration owidConfiguration,
            IPublicKeyStore? publicKeyStore = null)
        {
            _owidConfiguration = owidConfiguration;
            _publicKeyStore = publicKeyStore
                ?? new ConfigurationPublicKeyStore(owidConfiguration);
        }

        /// <summary>
        /// Returns the public key for the OWID creator. With a date, returns
        /// the key that was current at that date; without one, the current key.
        /// </summary>
        /// <param name="date">
        /// Optional date as minutes since 2020-01-01 UTC (the OWID date
        /// encoding).
        /// </param>
        /// <returns>
        /// The public key, or 404 when no key was active at the requested date.
        /// </returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [HttpGet("public-key")]
        [HttpPost("public-key")]
        public ActionResult<string?> GetPublicKey(uint? date = null)
        {
            var key = _publicKeyStore.GetPublicKey(date);
            if (date.HasValue && key == null)
            {
                return NotFound();
            }
            return key;
        }


        /// <summary>
        /// Returns the public key for the OWID creator.
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [HttpGet("creator")]
        [HttpPost("creator")]
        public string? GetCreator()
        {
            return _owidConfiguration.Domain;
        }
    }
}
