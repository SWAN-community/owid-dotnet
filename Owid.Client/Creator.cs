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
        /// <exception cref="ArithmeticException">
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
        public Model.Owid Sign(Model.Owid owid)
        {
            return SignWithOthers(owid, Constants.Empty);
        }

        /// <summary>
        /// Sign the OWID provided AND the other OWIDs provided.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        public Model.Owid Sign(
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
        public Model.Owid SignWithOthers(
            Model.Owid owid,
            Model.Owid[] others)
        {
            owid.Domain = Domain;
            owid.Date = DateTime.UtcNow;
            var data = owid.GetDataForCrypto(others);
            owid.Signature = Crypto.SignData(
                data,
                0,
                data.Length,
                HashAlgorithmName.SHA256);
            if (owid.Signature.Length != Constants.SignatureLength)
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
        public Model.Owid Sign(string value)
        {
            return Sign(ASCIIEncoding.ASCII.GetBytes(value));
        }

        /// <summary>
        /// Create a new OWID for the creator containing the value as the 
        /// payload.
        /// </summary>
        /// <param name="value">Payload value</param>
        /// <returns>Signed OWID with payload provided.</returns>
        public Model.Owid Sign(byte[] value)
        {
            var owid = new Model.Owid();
            owid.Payload = value;
            return Sign(owid);
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
