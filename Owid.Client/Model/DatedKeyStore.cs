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
    /// A signing public key together with the moment it comes into force.
    /// </summary>
    public class DatedPublicKey
    {
        /// <summary>
        /// The UTC moment from which this key signs. It stays in force until
        /// the next key starts, so the last key of a schedule covers every
        /// date after it.
        /// </summary>
        /// <remarks>
        /// This is the schedule position, not the moment the key material
        /// was generated. The two are not the same, because a creator may
        /// generate many weeks of keys in one run, and selecting on the
        /// moment of generation then picks a key whose period has not
        /// started. See <see cref="DatedKeyStore"/> for what that did.
        /// </remarks>
        public DateTime StartsAt { get; set; }

        /// <summary>
        /// The public key in PEM form.
        /// </summary>
        public string? PublicKey { get; set; }
    }

    /// <summary>
    /// <see cref="IPublicKeyStore"/> over a set of scheduled keys. Returns
    /// the key that was in force at the requested date, being the latest key
    /// whose <see cref="DatedPublicKey.StartsAt"/> is at or before it. A date
    /// that precedes every key yields null.
    /// </summary>
    /// <remarks>
    /// Selection runs on the schedule position of each key and not on the
    /// moment its material was generated. A creator may write many weeks of
    /// keys in one run, so the moment of generation says nothing about which
    /// key signed an identifier, and selecting on it picks a key whose period
    /// has not started and reports genuine identifiers as forged. The published
    /// schedule and an identifier signed under it are the fixture behind
    /// PublishedScheduleTests.
    /// </remarks>
    public class DatedKeyStore : IPublicKeyStore
    {
        // Sorted latest first once at construction so each lookup is a simple
        // scan rather than re-sorting on every request.
        private readonly IReadOnlyList<DatedPublicKey> _keysLatestFirst;

        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="keys">The known keys, in any order.</param>
        public DatedKeyStore(IEnumerable<DatedPublicKey> keys)
        {
            _keysLatestFirst = keys.OrderByDescending(k => k.StartsAt).ToList();
        }

        /// <inheritdoc/>
        public string? GetPublicKey(uint? dateMinutes)
        {
            if (dateMinutes == null)
            {
                // The key in force now, which is not the last key of the
                // schedule. A schedule is written ahead of time, so its last
                // entry is usually a key whose period has not begun, and
                // serving that as the current key would fail every check of
                // an identifier signed today.
                return InForceAt(DateTime.UtcNow);
            }

            // A date past the end of 9999 is after every key. Judged before
            // the arithmetic rather than caught after it, because AddMinutes
            // throws on such a count and the exception is a cost the caller
            // of the end point chooses.
            var requested = dateMinutes.Value > Constants.MaximumMinutes
                ? DateTime.MaxValue
                : Constants.BaseDate.AddMinutes(dateMinutes.Value);

            return InForceAt(requested);
        }

        private string? InForceAt(DateTime at) => _keysLatestFirst
            .FirstOrDefault(k => k.StartsAt <= at)?.PublicKey;

        /// <inheritdoc/>
        public PublicKeyPeriod? GetPublicKeyPeriod(uint? dateMinutes)
        {
            var at = dateMinutes == null
                ? DateTime.UtcNow
                : dateMinutes.Value > Constants.MaximumMinutes
                    ? DateTime.MaxValue
                    : Constants.BaseDate.AddMinutes(dateMinutes.Value);
            var index = -1;
            for (var i = 0; i < _keysLatestFirst.Count; i++)
            {
                if (_keysLatestFirst[i].StartsAt <= at)
                {
                    index = i;
                    break;
                }
            }
            if (index < 0 || _keysLatestFirst[index].PublicKey == null)
            {
                return null;
            }
            var key = _keysLatestFirst[index];
            // The span runs to the earliest later start, which is the
            // nearest key before this one in the latest first order that
            // does not share this one's start.
            DateTime? next = null;
            for (var i = index - 1; i >= 0; i--)
            {
                if (_keysLatestFirst[i].StartsAt > key.StartsAt)
                {
                    next = _keysLatestFirst[i].StartsAt;
                    break;
                }
            }
            return new PublicKeyPeriod(
                key.PublicKey!,
                Minutes(key.StartsAt),
                next == null ? null : Minutes(next.Value));
        }

        /// <summary>
        /// The moment as minutes since the base date, clamped to the count
        /// the OWID date can hold.
        /// </summary>
        private static uint Minutes(DateTime at)
        {
            if (at <= Constants.BaseDate)
            {
                return 0;
            }
            var minutes = (at - Constants.BaseDate).TotalMinutes;
            return minutes >= uint.MaxValue ? uint.MaxValue : (uint)minutes;
        }
    }
}
