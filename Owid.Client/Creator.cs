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
using System;
using System.Security.Cryptography;
using System.Text;

namespace Owid.Client
{
    /// <summary>
    /// Needed to create new OWIDs.
    /// </summary>
    public class Creator
    {
        /// <summary>
        /// Domain associated with the OWID creator. Contains well known end
        /// points to provide public keys and other information needed to 
        /// conform to the OWID specification.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// Used to sign OWIDs from this creator.
        /// </summary>
        public ECDsa Crypto { get; }

        /// <summary>
        /// Make new <see cref="Owid"/> from config.
        /// </summary>
        /// <param name="configuration">
        /// Configuration to use.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="configuration"/>.<see cref="OwidConfiguration.Domain"/> is empty or whitespace.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="configuration"/>.<see cref="OwidConfiguration.Domain"/> is longer than a domain can be.
        /// </exception>
        public Creator(OwidConfiguration configuration)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(
                configuration.Domain);
            ValidateDomain(configuration.Domain, nameof(configuration));
            Domain = configuration.Domain;

            // Reject an empty or whitespace PEM with a clear message rather
            // than relying on the opaque exception thrown by ImportFromPem.
            if (string.IsNullOrWhiteSpace(configuration.PrivateKey))
            {
                throw new ArgumentException("private key PEM is empty");
            }

            Crypto = ECDsa.Create();
            Crypto.ImportFromPem(configuration.PrivateKey);
            ValidateCrypto(Crypto);
        }

        /// <summary>
        /// Make new <see cref="Owid"/>.
        /// </summary>
        /// <param name="domain">
        /// Web domain to be used.
        /// </param>
        /// <param name="crypto">
        /// Crypto provider for signing <see cref="Owid"/>/-s.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="crypto" />'s <see cref="HashAlgorithmName.Name" /> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="crypto" />'s <see cref="HashAlgorithmName.Name" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="domain" /> is longer than a domain can be.
        /// </exception>
        public Creator(string domain, ECDsa crypto)
        {
            ValidateDomain(domain, nameof(domain));
            Domain = domain;
            ValidateCrypto(crypto);
            Crypto = crypto;
        }

        /// <summary>
        /// Sign the OWID provided.
        /// </summary>
        /// <param name="owid"></param>
        /// <returns></returns>
        internal Model.Owid Sign(Model.Owid owid)
        {
            return SignWithOthers(owid, Constants.Empty);
        }

        /// <summary>
        /// Sign the OWID provided AND the other OWIDs provided.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        internal Model.Owid Sign(
            Model.Owid owid,
            params Model.Owid[] others)
        {
            return SignWithOthers(owid, others);
        }

        /// <summary>
        /// Sign the OWID provided AND the other OWIDs provided.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        internal Model.Owid SignWithOthers(
            Model.Owid owid,
            Model.Owid[] others)
        {
            return SignWithOthers(owid, others, DateTime.UtcNow);
        }

        /// <summary>
        /// Sign the OWID provided AND the other OWIDs provided, stamping it
        /// with the date given rather than the moment of signing.
        /// </summary>
        internal Model.Owid SignWithOthers(
            Model.Owid owid,
            Model.Owid[] others,
            DateTime date)
        {
            owid.Domain = Domain;
            owid.Date = ToStampedDate(date);
            var data = owid.GetDataForCrypto(others);
            owid.SignatureInternal = Crypto.SignData(
                data,
                0,
                data.Length,
                HashAlgorithmName.SHA256);
            if (owid.SignatureInternal.Length != Constants.SignatureLength)
            {
                throw new Exception(
                    $@"Signatures must be '{Constants.SignatureLength}' " +
                    "bytes");
            }
            return owid;
        }

        /// <summary>
        /// Create a new OWID for the creator containing the value as the 
        /// payload.
        /// </summary>
        /// <param name="value">Payload value</param>
        /// <returns>Signed OWID with payload provided.</returns>
        public Model.Owid Create(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            return Create(ASCIIEncoding.ASCII.GetBytes(value));
        }

        /// <summary>
        /// Create a new OWID for the creator containing the value as the 
        /// payload.
        /// </summary>
        /// <param name="value">Payload value</param>
        /// <returns>Signed OWID with payload provided.</returns>
        public Model.Owid Create(byte[] value)
        {
            return Create(value, Constants.Empty);
        }

        /// <summary>
        /// Creates and signs an OWID carrying the value, with the other OWIDs
        /// covered by the signature so that a tree can be verified as a whole.
        /// </summary>
        /// <param name="value">Payload value</param>
        /// <param name="others">
        /// OWIDs this one is signed alongside.
        /// </param>
        /// <returns>Signed OWID with the payload provided.</returns>
        /// <remarks>
        /// This is one of only two ways an OWID reaches calling code, the
        /// other being a successful parse. The creator owns the version, the
        /// domain, the date and the signature; a caller supplies the payload
        /// and nothing else, so there is no moment at which a partly built
        /// OWID exists for anyone to hold or pass on.
        /// </remarks>
        public Model.Owid Create(byte[] value, params Model.Owid[] others)
        {
            return Create(value, DateTime.UtcNow, others);
        }

        /// <summary>
        /// Creates and signs an OWID carrying the value and the date, with
        /// the other OWIDs covered by the signature.
        /// </summary>
        /// <param name="value">Payload value</param>
        /// <param name="date">
        /// The date the OWID states. A caller that wants an OWID to say less
        /// than the moment it was made - the day rather than the minute, say,
        /// so that two identifiers issued to the same person an hour apart
        /// cannot be told apart by their dates - supplies that date here.
        /// Converted to UTC, and truncated to the whole minute the wire
        /// format carries, so the OWID in hand states exactly what its bytes
        /// state.
        /// </param>
        /// <param name="others">
        /// OWIDs this one is signed alongside.
        /// </param>
        /// <returns>Signed OWID with the payload and date provided.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="date"/> is before the base date the format counts
        /// minutes from. That date cannot be written, and casting it into the
        /// count would silently record a far later one.
        /// </exception>
        public Model.Owid Create(
            byte[] value,
            DateTime date,
            params Model.Owid[] others)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            var owid = new Model.Owid();
            owid.PayloadInternal = (byte[])value.Clone();
            return SignWithOthers(owid, others ?? Constants.Empty, date);
        }

        /// <summary>
        /// The date as the OWID will state it: UTC, and whole minutes,
        /// because versions 2 and 3 count minutes since
        /// <see cref="Constants.BaseDate"/> and anything finer is dropped on
        /// the way to the bytes. Doing it here means the OWID a caller holds
        /// says the same thing as the OWID it hands on, which matters because
        /// the signature covers the bytes.
        /// </summary>
        /// <remarks>
        /// A date of <see cref="DateTimeKind.Unspecified"/> is taken as UTC.
        /// The alternative, reading it as local time, would silently move an
        /// identifier by the machine's offset and make the same call produce
        /// different OWIDs on different servers.
        /// </remarks>
        private static DateTime ToStampedDate(DateTime date)
        {
            var utc = date.Kind == DateTimeKind.Local
                ? date.ToUniversalTime()
                : DateTime.SpecifyKind(date, DateTimeKind.Utc);
            if (utc < Constants.BaseDate)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(date),
                    utc,
                    "an OWID counts minutes from " +
                    $"'{Constants.BaseDate:u}' and cannot state a date " +
                    "before it");
            }
            // No upper bound is needed. The wire format's four byte count
            // runs past the end of the year 9999, which is where a DateTime
            // stops, so every date a caller can hand over fits once it is
            // cut to whole minutes. The reader has the opposite problem and
            // guards it: the bytes can state a minute this runtime cannot
            // hold.
            var minutes = (utc - Constants.BaseDate).Ticks
                / TimeSpan.TicksPerMinute;
            return Constants.BaseDate.AddMinutes(minutes);
        }

        /// <summary>
        /// Refuses a creator domain longer than the maximum a domain can
        /// have, being the same maximum the envelope read uses, at the
        /// point the caller supplies the domain. Taking the domain here
        /// means the caller is told where they gave the value, before any
        /// key is used and before anything is signed or serialised, rather
        /// than at the consumer that later cannot parse the result. The
        /// serialisation of the domain refuses the same value again, so a
        /// domain that arrives by some other route is still refused. A
        /// domain at or under the maximum, and an absent domain, behave
        /// exactly as they did before.
        /// </summary>
        private static void ValidateDomain(string domain, string parameterName)
        {
            if (domain is not null &&
                domain.Length > Constants.MaximumDomainLength)
            {
                throw new ArgumentException(
                    $@"Creator domain of '{domain.Length}' characters is " +
                    $@"longer than the '{Constants.MaximumDomainLength}' " +
                    "characters a domain can have",
                    parameterName);
            }
        }

        private static void ValidateCrypto(ECDsa crypto)
        {
            var test = new byte[128];
            var written = crypto.SignData(
                [0],
                test,
                HashAlgorithmName.SHA256);
        }
    }
}
