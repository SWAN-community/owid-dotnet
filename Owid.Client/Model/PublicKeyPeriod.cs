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
using System.Text.Json.Serialization;

namespace Owid.Client.Model
{
    /// <summary>
    /// A signing public key together with the span it covers, as minutes
    /// since 2020-01-01 UTC, the count the OWID date and the public key end
    /// point's <c>date</c> parameter use.
    /// </summary>
    public class PublicKeyPeriod
    {
        /// <summary>
        /// Designated constructor.
        /// </summary>
        /// <param name="publicKey">The key in PEM form.</param>
        /// <param name="startsAt">
        /// The minute the key came into force.
        /// </param>
        /// <param name="endsAt">
        /// The minute the next key starts, or null when no later key has
        /// been scheduled and the key is in force until further notice.
        /// </param>
        public PublicKeyPeriod(string publicKey, uint startsAt, uint? endsAt)
        {
            PublicKey = publicKey;
            StartsAt = startsAt;
            EndsAt = endsAt;
        }

        /// <summary>
        /// The key in PEM form.
        /// </summary>
        public string PublicKey { get; }

        /// <summary>
        /// The minute the key came into force.
        /// </summary>
        public uint StartsAt { get; }

        /// <summary>
        /// The minute the next key starts, or null when none is scheduled.
        /// </summary>
        public uint? EndsAt { get; }
    }

    /// <summary>
    /// The JSON body of the public key end point. It carries the key together
    /// with the moments it is valid from and to, in UTC, so a client holds
    /// the key for the whole span from one answer rather than asking again
    /// for every minute. The PEM alone as text is not a valid answer.
    /// </summary>
    public class PublicKeyResponse
    {
        /// <summary>
        /// The public key in PEM form.
        /// </summary>
        [JsonPropertyName("publicKeySPKI")]
        public string PublicKeySPKI { get; set; } = string.Empty;

        /// <summary>
        /// The UTC moment the key came into force, or null where the creator
        /// does not know when it started.
        /// </summary>
        [JsonPropertyName("validFrom")]
        public DateTime? ValidFrom { get; set; }

        /// <summary>
        /// The UTC moment the next key starts, or null where no later key has
        /// been scheduled and the key is in force until further notice.
        /// </summary>
        [JsonPropertyName("validTo")]
        public DateTime? ValidTo { get; set; }

        /// <summary>
        /// The answer for the key in force at the moment asked about, with
        /// the span where the store knows it, checked before it is returned
        /// so that a creator never sends an answer it would itself refuse.
        /// </summary>
        /// <param name="publicKey">The key in PEM form.</param>
        /// <param name="period">The span, or null where it is not known.</param>
        /// <param name="askedMinutes">
        /// The moment asked about as minutes since 2020-01-01 UTC, after a
        /// date later than now has been read as now.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The answer fails <see cref="Validate"/>.
        /// </exception>
        public static PublicKeyResponse For(
            string publicKey,
            PublicKeyPeriod? period,
            uint askedMinutes)
        {
            var response = new PublicKeyResponse { PublicKeySPKI = publicKey };
            if (period != null)
            {
                response.ValidFrom = Constants.BaseDate.AddMinutes(period.StartsAt);
                if (period.EndsAt != null)
                {
                    response.ValidTo = Constants.BaseDate.AddMinutes(period.EndsAt.Value);
                }
            }
            response.Validate(Constants.BaseDate.AddMinutes(askedMinutes));
            return response;
        }

        /// <summary>
        /// Checks the answer the way both the creator that sends it and the
        /// client that reads it must. The key must be a public key this
        /// library can read, a key valid to a moment must be valid from an
        /// earlier one, and where the moment asked about is known the key
        /// must have come into force by then and, if it has an end, not have
        /// ended. A creator that fails this check has a fault in its schedule
        /// or its store, and answering with a server error shows it up rather
        /// than passing it on.
        /// </summary>
        /// <param name="asked">The moment asked about, or null.</param>
        /// <exception cref="InvalidOperationException">
        /// The answer is not valid.
        /// </exception>
        public void Validate(DateTime? asked)
        {
            if (string.IsNullOrWhiteSpace(PublicKeySPKI))
            {
                throw new InvalidOperationException(
                    "the public key answer holds no key");
            }
            try
            {
                using var key = System.Security.Cryptography.ECDsa.Create();
                key.ImportFromPem(PublicKeySPKI);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(
                    "the public key answer holds a key that cannot be read", e);
            }
            if (ValidTo != null)
            {
                if (ValidFrom == null)
                {
                    throw new InvalidOperationException(
                        "the public key answer states when the key ends but not when it started");
                }
                if (ValidTo.Value <= ValidFrom.Value)
                {
                    throw new InvalidOperationException(
                        "the public key answer states a key that ends before it starts");
                }
            }
            if (asked != null)
            {
                if (ValidFrom != null && ValidFrom.Value > asked.Value)
                {
                    throw new InvalidOperationException(
                        "the public key answer states a key that had not started at the moment asked about");
                }
                if (ValidTo != null && ValidTo.Value <= asked.Value)
                {
                    throw new InvalidOperationException(
                        "the public key answer states a key that had ended at the moment asked about");
                }
            }
        }
    }
}
