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

namespace Owid.Client.Model
{
    /// <summary>
    /// Source of the OWID creator's signing public keys for the public-key
    /// end point. Implement this to serve historical keys for a creator that
    /// rotates its signing key.
    /// </summary>
    public interface IPublicKeyStore
    {
        /// <summary>
        /// The public key (PEM) that was current at the given date, expressed
        /// as minutes since 2020-01-01 UTC (the OWID date encoding). When the
        /// date is null the current key is returned. Returns null when the date
        /// predates the oldest known key.
        /// </summary>
        /// <param name="dateMinutes">
        /// Minutes since 2020-01-01 UTC, or null for the current key.
        /// </param>
        string? GetPublicKey(uint? dateMinutes);
    }
}
