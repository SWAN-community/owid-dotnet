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

namespace Owid.Client.Model.Configuration
{ 
    /// <summary>
    /// Configuration for <see cref="Creator"/>
    /// to make new <see cref="Owid"/>s with.
    /// </summary>
    public class OwidConfiguration
    {
        /// <summary>
        /// Domain associated with the OWID creator. Contains well known end
        /// points to provide public keys and other information needed to 
        /// conform to the OWID specification.
        /// </summary>
        public string? Domain { get; set; }

        /// <summary>
        /// The PEM format private key for the OWID creator.
        /// </summary>
        public string? PrivateKey { get; set; }

        /// <summary>
        /// The PEM format public key for the OWID creator.
        /// </summary>
        public string? PublicKey { get; set; }
    }
}
