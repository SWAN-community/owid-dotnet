﻿/* ****************************************************************************
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
        public RSACryptoServiceProvider RSA { get; }

        public Creator(OwidConfiguration configuration)
        {
            Domain = configuration.Domain;
            RSA = new RSACryptoServiceProvider(512);
            RSA.ImportFromPem(configuration.PrivateKey);
            ValidateRsa(RSA);
        }

        public Creator(string domain, RSACryptoServiceProvider rsa)
        {
            Domain = domain;
            ValidateRsa(rsa);
            RSA = rsa;
        }

        public Model.Owid Sign(Model.Owid owid)
        {
            return SignWithOthers(owid, Constants.Empty);
        }

        public Model.Owid Sign(
            Model.Owid owid,
            params Model.Owid[] others)
        {
            return SignWithOthers(owid, others);
        }

        public Model.Owid SignWithOthers(
            Model.Owid owid,
            Model.Owid[] others)
        {
            owid.Domain = Domain;
            owid.Date = DateTime.UtcNow;
            var data = owid.GetDataForCrypto(others);
            owid.Signature = RSA.SignData(
                data,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            if (owid.Signature.Length != Constants.SignatureLength)
            {
                throw new Exception(
                    $@"Signatures must be '{Constants.SignatureLength}' " +
                    "bytes");
            }
            return owid;
        }

        private static void ValidateRsa(RSACryptoServiceProvider rsa)
        {
            if (rsa.PublicOnly)
            {
                throw new ArgumentException(
                    "RSACryptoServiceProvider must support private signing" +
                    "to be used with Creator",
                    "rsa");
            }
        }
    }
}