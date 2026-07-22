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

using Owid.Client.Model.Configuration;

namespace Owid.Client.Model
{
    /// <summary>
    /// Default <see cref="IPublicKeyStore"/> backed by the single key in
    /// <see cref="OwidConfiguration"/>. A creator with one long-lived key has
    /// no key history, so the date is ignored.
    /// </summary>
    public class ConfigurationPublicKeyStore : IPublicKeyStore
    {
        private readonly OwidConfiguration _configuration;

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="configuration">The OWID creator configuration.</param>
        public ConfigurationPublicKeyStore(OwidConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <inheritdoc/>
        public string? GetPublicKey(uint? dateMinutes)
        {
            return _configuration.PublicKey;
        }
    }
}
