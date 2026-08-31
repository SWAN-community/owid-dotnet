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
    /// The outcome of asking whether an OWID's signature is genuine.
    /// </summary>
    /// <remarks>
    /// Only two of these say anything about the signature itself. The rest say
    /// the question could not be answered, which is a different thing and must
    /// never be reported as a forgery. A key that cannot be fetched, a key
    /// that cannot be decoded, or a provider that fails leaves the signature
    /// unjudged. Collapsing those into "invalid" tells a caller that data was
    /// tampered with when all that happened is that we could not check, and a
    /// caller acting on that would reject good identifiers during an outage.
    ///
    /// This is not hypothetical. On 30 August 2026 the key endpoints published
    /// PEM wrapped at 76 characters, which a strict parser rejects, and every
    /// offline verification against them failed. The keys were fine and the
    /// identifiers were fine. Reported as InvalidKey that reads as the
    /// operational fault it was; reported as SignatureInvalid it would have
    /// read as an attack.
    /// </remarks>
    public enum OwidSignatureStatus
    {
        /// <summary>
        /// The signature is genuine for this data and this key.
        /// </summary>
        SignatureValid = 0,

        /// <summary>
        /// The signature is well formed and does not match. The data does not
        /// belong to the key it claims. This is the only status that means the
        /// identifier should be distrusted.
        /// </summary>
        SignatureInvalid = 1,

        /// <summary>
        /// A signature field of the wrong length reached a verification
        /// surface directly. Truncation in raw external input is a parse
        /// <see cref="OwidParseStatus.UnexpectedEnd"/> instead, because there
        /// the envelope never formed.
        /// </summary>
        InvalidSignatureLength = 2,

        /// <summary>
        /// No key could be obtained, or none covers the identifier's date.
        /// The signature was never examined.
        /// </summary>
        KeyUnavailable = 3,

        /// <summary>
        /// Key material arrived but cannot be decoded, imported, or used as
        /// the required type. The fault is in the key, not the identifier.
        /// </summary>
        InvalidKey = 4,

        /// <summary>
        /// The work required exceeds what this runtime can represent or hold.
        /// </summary>
        ImplementationCapacityExceeded = 5,

        /// <summary>
        /// The check could not be completed for a reason that is not the
        /// identifier's fault, such as a malformed key-list response or a
        /// cryptographic provider failing on valid inputs.
        /// </summary>
        VerificationError = 6,
    }
}
