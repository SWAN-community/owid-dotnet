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
    /// Why a parse of external data succeeded or failed.
    /// </summary>
    /// <remarks>
    /// Malformed data arriving from outside is expected, not exceptional. An
    /// OWID is read from whatever a caller was given, which on a public
    /// endpoint means anything at all, so every one of these outcomes is a
    /// normal result rather than a fault. Reporting them as exceptions costs
    /// the construction and unwinding of an exception per bad input, which is
    /// a cost an attacker chooses the size of.
    ///
    /// These names are the cross-language vocabulary. Each implementation
    /// spells the surface in its own idiom, but the set of facts reported is
    /// the same everywhere, so a failure means the same thing whichever
    /// language read the bytes.
    /// </remarks>
    public enum OwidParseStatus
    {
        /// <summary>
        /// The bytes form a structurally valid OWID. This says nothing about
        /// the signature, which is a separate question answered separately.
        /// </summary>
        Parsed = 0,

        /// <summary>
        /// Nothing was supplied to parse.
        /// </summary>
        MissingInput = 1,

        /// <summary>
        /// The input was supplied in a form this surface cannot read.
        /// </summary>
        InvalidInputType = 2,

        /// <summary>
        /// The string is not valid Base64, so there are no bytes to read.
        /// </summary>
        InvalidBase64 = 3,

        /// <summary>
        /// The first byte names a version this implementation does not know.
        /// </summary>
        UnsupportedVersion = 4,

        /// <summary>
        /// The data stopped in the middle of a field. Distinct from
        /// <see cref="ByteCountMismatch"/>, which is a declaration that
        /// disagrees with data that is all present.
        /// </summary>
        UnexpectedEnd = 5,

        /// <summary>
        /// The creator domain is not terminated, or is longer than the
        /// published maximum.
        /// </summary>
        InvalidDomainEncoding = 6,

        /// <summary>
        /// The declared payload byte count disagrees with the bytes actually
        /// present. Checked before anything is sized by the declaration, so a
        /// sender cannot make a reader allocate by claiming a large payload it
        /// did not send.
        /// </summary>
        ByteCountMismatch = 7,

        /// <summary>
        /// The envelope is structurally consistent but larger than this
        /// runtime can represent or hold. Not a fault in the data, and
        /// deliberately distinct from the data being wrong, because the same
        /// bytes may be readable elsewhere.
        /// </summary>
        ImplementationCapacityExceeded = 8,

        /// <summary>
        /// The envelope is malformed in a way none of the above describes.
        /// A fallback for the genuinely unclassified, not a substitute for
        /// naming a failure that is already understood.
        /// </summary>
        MalformedEnvelope = 9,
    }
}
