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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
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
					DecompressionMethods.GZip | DecompressionMethods.Deflate,
				// Never follow a redirect. The handler follows up to fifty
				// by default, to any other host, so a creator whose domain
				// answered 302 to some other place would have that other
				// place's key trusted as its own, and a network attacker
				// able to bend the creator's DNS, or a creator that was
				// simply misconfigured, could put a key there and have
				// forgeries verify. Left alone, the 3xx is a non success
				// code and GetStringAsync throws, which is how every other
				// failure to obtain the key already surfaces here.
				AllowAutoRedirect = false
			};

		/// <summary>
		/// The most public keys held at once. The cache is emptied rather
		/// than trimmed when it reaches this, which costs the keys still in
		/// use one request each as they are asked for again and keeps the
		/// bookkeeping to a count. The Java and Python ports hold the same
		/// number the same way.
		/// </summary>
		private const int MaximumCachedKeys = 1024;

		/// <summary>
		/// Cache used to avoid repeat requests for the same public keys. One
		/// entry per key URL, holding the fetch, so that callers arriving
		/// together share one request rather than each making their own and
		/// a caller arriving later is answered without one.
		/// </summary>
		/// <remarks>
		/// A key URL carries the domain and the date of the OWID being
		/// verified, neither of which this process chooses, so the number of
		/// distinct URLs is set by the OWIDs presented to it. The cache is
		/// therefore bounded by <see cref="MaximumCachedKeys"/>.
		/// </remarks>
		private static readonly ConcurrentDictionary<
			Uri,
			Task<string>> _publicKeyCache =
			new ConcurrentDictionary<
				Uri,
				Task<string>>();

		/// <summary>
		/// Verify that <see cref="Owid"/> signature is correct, fetching the
		/// public key from the creator's domain over HTTPS.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="cancellationToken">
		/// Ends this caller's wait for the key. See
		/// <see cref="GetPublicKeyAsync(Uri, CancellationToken)"/> for what
		/// that does and does not cancel.
		/// </param>
		/// <returns></returns>
		public static Task<bool> VerifyAsync(
			this Model.Owid owid,
			CancellationToken cancellationToken = default)
		{
			return owid.VerifyAsync(Constants.Empty, cancellationToken);
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
        /// Verify that <see cref="Owid"/> signature is correct over the
        /// others it was signed with, fetching the public key from the
        /// creator's domain over HTTPS.
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="others"></param>
        /// <param name="cancellationToken">
        /// Ends this caller's wait for the key. See
        /// <see cref="GetPublicKeyAsync(Uri, CancellationToken)"/> for what
        /// that does and does not cancel.
        /// </param>
        /// <returns></returns>
        public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			Model.Owid[] others,
			CancellationToken cancellationToken = default)
		{
			using (var crypto = await owid.GetPublicKeyAsync(
				"https",
				cancellationToken).ConfigureAwait(false))
			{
				return owid.Verify(crypto, others);
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
            if (owid.SignatureInternal.Length != Constants.SignatureLength)
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
		/// Gets the public key for the owid from the creator's domain.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="scheme"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		private static async Task<ECDsa> GetPublicKeyAsync(
			this Model.Owid owid,
			string scheme,
			CancellationToken cancellationToken)
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
			var publicKeyPem = await GetPublicKeyAsync(
				u.Uri,
				cancellationToken).ConfigureAwait(false);

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
		/// Get the public key PEM from the URL if it is not already in the
		/// cache. Callers arriving while a fetch for the same URL is in
		/// flight share that fetch rather than starting their own.
		/// </summary>
		/// <remarks>
		/// The token ends this caller's wait, not the shared request. A
		/// request one caller started is usually the request every other
		/// caller for the same key is waiting on, so letting one caller
		/// abandon the request for all of them would turn one timeout into
		/// many. The request runs to completion and the next caller finds
		/// the key in the cache.
		/// </remarks>
		/// <param name="u"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
        // Internal rather than private so the test project can point it
        // at a stand in end point by URL, since the domain an OWID carries
        // cannot name a port.
        internal static Task<string> GetPublicKeyAsync(
			Uri u,
			CancellationToken cancellationToken = default)
        {
			if (_publicKeyCache.TryGetValue(u, out var held) == false)
			{
				// Emptied rather than allowed to grow without limit, because
				// the URLs asked for come from the OWIDs presented to this
				// process rather than from the process itself.
				if (_publicKeyCache.Count >= MaximumCachedKeys)
				{
					_publicKeyCache.Clear();
				}
				var source = new TaskCompletionSource<string>(
					TaskCreationOptions.RunContinuationsAsynchronously);
				held = _publicKeyCache.GetOrAdd(u, source.Task);
				if (ReferenceEquals(held, source.Task))
				{
					// This caller is the one that added the entry, so this
					// caller is the one that performs the request. Every
					// other caller waits on the task just added.
					_ = FetchIntoAsync(u, source);
				}
			}
			return held.WaitAsync(cancellationToken);
        }

		/// <summary>
		/// Perform the request for <paramref name="u"/> and put its outcome
		/// into <paramref name="source"/>, which is the task every caller
		/// for that URL is waiting on.
		/// </summary>
		/// <remarks>
		/// A fetch that fails is taken out of the cache, so the next caller
		/// makes a fresh request rather than being handed the old failure.
		/// The entry is matched on identity as well as URL, so a fetch that
		/// fails after the cache was emptied and filled again removes only
		/// itself and never whatever replaced it.
		/// </remarks>
		private static async Task FetchIntoAsync(
			Uri u,
			TaskCompletionSource<string> source)
		{
			try
			{
				var publicKey = await new HttpClient(_handler)
					.GetStringAsync(u)
					.ConfigureAwait(false);
				source.SetResult(publicKey);
			}
			catch (Exception e)
			{
				_publicKeyCache.TryRemove(
					new KeyValuePair<Uri, Task<string>>(u, source.Task));
				source.SetException(e);
			}
		}

		/// <summary>
		/// Empty the public key cache, so that the next verification of any
		/// OWID fetches the creator's key again. The Java and Python ports
		/// offer the same.
		/// </summary>
		public static void ClearPublicKeyCache()
		{
			_publicKeyCache.Clear();
		}
	}
}