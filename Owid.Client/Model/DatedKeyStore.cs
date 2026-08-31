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

using System;
using System.Collections.Generic;
using System.Linq;

namespace Owid.Client.Model
{
    /// <summary>
    /// A signing public key together with the date it was created.
    /// </summary>
    public class DatedPublicKey
    {
        /// <summary>
        /// The UTC date the key was created.
        /// </summary>
        public DateTime Created { get; set; }

        /// <summary>
        /// The public key in PEM form.
        /// </summary>
        public string? PublicKey { get; set; }
    }

    /// <summary>
    /// <see cref="IPublicKeyStore"/> over a set of dated keys. Returns the key
    /// that was current at the requested date: the newest key created on or
    /// before it. A date that predates every key yields null.
    /// </summary>
    public class DatedKeyStore : IPublicKeyStore
    {
        // Sorted newest first once at construction so each lookup is a simple
        // scan rather than re-sorting on every request.
        private readonly IReadOnlyList<DatedPublicKey> _keysNewestFirst;

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="keys">The known keys, in any order.</param>
        public DatedKeyStore(IEnumerable<DatedPublicKey> keys)
        {
            _keysNewestFirst = keys.OrderByDescending(k => k.Created).ToList();
        }

        /// <inheritdoc/>
        public string? GetPublicKey(uint? dateMinutes)
        {
            if (dateMinutes == null)
            {
                return _keysNewestFirst.FirstOrDefault()?.PublicKey;
            }

            // A date past the end of 9999 is after every key. Judged before
            // the arithmetic rather than caught after it, because AddMinutes
            // throws on such a count and the exception is a cost the caller
            // of the end point chooses.
            var requested = dateMinutes.Value > Constants.MaximumMinutes
                ? DateTime.MaxValue
                : Constants.BaseDate.AddMinutes(dateMinutes.Value);

            return _keysNewestFirst
                .FirstOrDefault(k => k.Created <= requested)?.PublicKey;
        }
    }
}
