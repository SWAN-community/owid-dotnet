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

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="owidConfiguration"></param>
        public OwidController(OwidConfiguration owidConfiguration)
        {
            _owidConfiguration = owidConfiguration;
        }

        /// <summary>
        /// Returns the public key for the OWID creator.
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [HttpGet("public-key")]
        [HttpPost("public-key")]
        public string? GetPublicKey()
        {
            return _owidConfiguration.PublicKey;
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
