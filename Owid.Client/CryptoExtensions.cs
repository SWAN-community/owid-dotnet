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
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Owid.Client.Model;

namespace Owid.Client
{
	/// <summary>
	/// Extensions methods for crypto operations
	/// on <see cref="Owid"/> instances.
	/// </summary>
    public static class CryptoExtensions
    {
		/// <summary>
		/// Handlers used with HTTP clients to automatically decompress any
		/// compressed data streams.
		/// </summary>
		private static readonly HttpClientHandler _handler =
			new HttpClientHandler()
			{
				AutomaticDecompression =
					DecompressionMethods.GZip | DecompressionMethods.Deflate
			};

		/// <summary>
		/// Cache used to avoid repeat requests for the same public keys.
		/// </summary>
		private static readonly ConcurrentDictionary<
			Uri,
			WeakReference<string>> _publicKeyCache = 
			new ConcurrentDictionary<
				Uri, 
				WeakReference<string>>();

		/// <summary>
		/// Verify that <see cref="Owid"/> signature is correct.
		/// </summary>
		/// <param name="owid"></param>
		/// <returns></returns>
		public static async Task<bool> VerifyAsync(this Model.Owid owid)
		{
			using (var crypto = owid.GetPublicKey("https"))
			{
				return await owid.VerifyAsync(crypto, Constants.Empty);
			}
		}

        /// <summary>
        /// Verify that <see cref="Owid"/> signature is correct.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="crypto"></param>
        /// <returns></returns>
        public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			ECDsa crypto)
        {
			return await owid.VerifyAsyncWithOthers(crypto, Constants.Empty);
		}

        /// <summary>
        /// Verify that <see cref="Owid"/> signature is correct.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			params Model.Owid[] others)
		{
			using (var crypto = owid.GetPublicKey("https"))
			{
				return await owid.VerifyAsyncWithOthers(crypto, others);
			}
		}

        /// <summary>
        /// Verify that <see cref="Owid"/> signature is correct.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="crypto"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			ECDsa crypto,
			params Model.Owid[] others)
        {
			return await owid.VerifyAsyncWithOthers(crypto, others);
		}

        /// <summary>
        /// Says whether the signature is genuine, or why that could not be
        /// decided.
        /// </summary>
        /// <remarks>
        /// Only two of the answers are about the signature. The rest say the
        /// question could not be answered, which is a different thing and must
        /// never be reported as a forgery. A key that cannot be decoded leaves
        /// the signature unjudged, and a caller acting on "invalid" would
        /// reject good identifiers during an outage. On 30 August 2026 the key
        /// endpoints served PEM a strict parser rejects and every offline
        /// verification failed, with the keys and the identifiers both fine.
        /// </remarks>
        public static OwidSignatureStatus SignatureStatus(
            this Model.Owid owid,
            ECDsa crypto,
            params Model.Owid[] others)
        {
            if (owid == null)
            {
                throw new ArgumentNullException(nameof(owid));
            }
            if (crypto == null)
            {
                return OwidSignatureStatus.KeyUnavailable;
            }
            if (owid.Signature.Length != Constants.SignatureLength)
            {
                return OwidSignatureStatus.InvalidSignatureLength;
            }
            try
            {
                return owid.Verify(crypto, others)
                    ? OwidSignatureStatus.SignatureValid
                    : OwidSignatureStatus.SignatureInvalid;
            }
            catch (CryptographicException)
            {
                // The provider failed on inputs that were themselves fine.
                return OwidSignatureStatus.VerificationError;
            }
        }

        /// <summary>
        /// Says whether the signature is genuine using the public key in PEM
        /// form, or why that could not be decided.
        /// </summary>
        public static OwidSignatureStatus SignatureStatus(
            this Model.Owid owid,
            string publicKeyPem,
            params Model.Owid[] others)
        {
            if (string.IsNullOrEmpty(publicKeyPem))
            {
                return OwidSignatureStatus.KeyUnavailable;
            }
            ECDsa crypto;
            try
            {
                crypto = ECDsa.Create();
                crypto.ImportFromPem(publicKeyPem);
            }
            catch (Exception ex) when (
                ex is ArgumentException ||
                ex is CryptographicException ||
                ex is FormatException)
            {
                // The key is the thing at fault, not the identifier. This is
                // the case that happened: PEM a strict parser rejects.
                return OwidSignatureStatus.InvalidKey;
            }
            using (crypto)
            {
                return owid.SignatureStatus(crypto, others);
            }
        }

        /// <summary>
        /// Verify that <see cref="Owid"/> signature is correct without any
        /// asynchronous machinery. Verification is a short CPU-bound
        /// operation, so callers on a request path should prefer this over
        /// the asynchronous methods, which remain for compatibility.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="crypto"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        public static bool Verify(
			this Model.Owid owid,
			ECDsa crypto,
			params Model.Owid[] others)
		{
			var data = owid.GetDataForCrypto(others ?? Constants.Empty);
			return crypto.VerifyData(
				data,
				owid.Signature,
				HashAlgorithmName.SHA256);
		}

        /// <summary>
        /// Verify that <see cref="Owid"/> signature is correct.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="crypto"></param>
        /// <param name="others"></param>
        /// <returns></returns>
        public static Task<bool> VerifyAsyncWithOthers(
			this Model.Owid owid,
			ECDsa crypto,
			Model.Owid[] others)
		{
			// Completes synchronously. The previous implementation queued
			// the check to the thread pool with Task.Run, which cost a pool
			// thread and a hop for a sub-millisecond CPU-bound operation,
			// and callers that block on the result then held two threads
			// per verification.
			return Task.FromResult(owid.Verify(crypto, others));
		}

		/// <summary>
		/// Adds the fields from this OWID to the byte buffer without the 
		/// signature. Adds all the bytes of the others to the data.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="others"></param>
		/// <returns></returns>
		internal static byte[] GetDataForCrypto(
			this Model.Owid owid,
			Model.Owid[] others)
        {
			// With no others the data is exactly the signed bytes, which is
			// the common case on the verification path.
			if (others.Length == 0)
			{
				return owid.GetSignedBytes();
			}
			var size = owid.GetSignedByteCount();
			foreach (var other in others)
			{
				size += other.GetByteCount();
			}
			return Extensions.ToExactBuffer(
				size,
				(owid, others),
				static (writer, state) =>
				{
					state.owid.ToBufferNoSignature(writer);
					foreach (var other in state.others)
					{
						other.ToBuffer(writer);
					}
				});
        }

		/// <summary>
		/// Gets the public key for the owid.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="scheme"></param>
		/// <returns></returns>
		private static ECDsa GetPublicKey(
			this Model.Owid owid,
			string scheme)
        {
            // Construct the URL to get the public key.
            UriBuilder u = new UriBuilder(
                scheme,
                owid.Domain);
            u.Path = @$"/owid/api/v{(byte)owid.Version}/public-key";
            // Send the OWID's own date so a creator that rotates keys returns
            // the key that was current when the OWID was signed, letting OWIDs
            // created before a rotation still verify. Creators that do not
            // support dated lookup ignore it and return the current key.
            u.Query = owid.Date >= Constants.BaseDate
                ? @$"format=pkcs&date={(uint)(owid.Date - Constants.BaseDate).TotalMinutes}"
                : "format=pkcs";

			// Fetch the public key PEM associated with the OWID.
			var publicKeyPem = GetPublicKey(u.Uri);

			// Reject an empty or whitespace PEM with a clear message rather
			// than relying on the opaque exception thrown by ImportFromPem.
			if (string.IsNullOrWhiteSpace(publicKeyPem))
			{
				throw new ArgumentException("public key PEM is empty");
			}

			// Create the ECDsa provider with the public key associated with
			// the OWID.
			var key = ECDsa.Create();
			key.ImportFromPem(publicKeyPem);
			return key;
        }

		/// <summary>
		/// Get the public key from the domain contained in the OWID if it is 
		/// not already contained in the cache.
		/// </summary>
		/// <param name="u"></param>
		/// <returns></returns>
        private static string GetPublicKey(Uri u)
        {
			var publicKeyRef = _publicKeyCache.GetOrAdd(
				u,
				(u) =>
				{
					return new WeakReference<string>(new HttpClient(
						_handler).GetStringAsync(u).Result);
				});
            if (publicKeyRef.TryGetTarget(out var publicKey) == false)
            {
				publicKey = new HttpClient(_handler).GetStringAsync(u).Result;
				publicKeyRef.SetTarget(publicKey);
			}
			return publicKey;
        }
    }
}
