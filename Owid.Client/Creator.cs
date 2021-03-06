/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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

        public Creator(OwidConfiguration configuration)
        {
            Domain = configuration.Domain;
            Crypto = ECDsa.Create();
            Crypto.ImportFromPem(configuration.PrivateKey);
            ValidateCrypto(Crypto);
        }

        public Creator(string domain, ECDsa crypto)
        {
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

        private static void ValidateCrypto(ECDsa crypto)
        {
            var test = new Span<byte>();
            var written = 0;
            if (crypto.TrySignData(
                new byte[] { 0 }, 
                test, 
                HashAlgorithmName.SHA256, 
                out written) == false || 
                written == 0)
            {
                throw new ArgumentException(
                    "ECDsa provider must support private signing " +
                    "to be used with Creator",
                    "crypto");
            }
        }
    }
}
