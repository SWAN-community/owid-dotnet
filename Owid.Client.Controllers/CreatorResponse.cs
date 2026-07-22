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

using System.Text.Json.Serialization;

namespace Owid.Client.Controllers
{
    /// <summary>
    /// The creator end point response, per the SWAN OWID spec. Carries the
    /// creator domain and the signing public key in SPKI form, so a consumer
    /// can cache the key without a second call. With a date the key that was
    /// current then is returned, matching the public-key end point.
    /// </summary>
    public class CreatorResponse
    {
        /// <summary>
        /// The domain the key relates to.
        /// </summary>
        [JsonPropertyName("domain")]
        public string? Domain { get; set; }

        /// <summary>
        /// The signing public key in SPKI form.
        /// </summary>
        [JsonPropertyName("publicKeySPKI")]
        public string? PublicKeySPKI { get; set; }
    }
}
