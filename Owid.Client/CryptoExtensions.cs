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
		/// Cache used to avoid repeat requests for the same public keys. One
		/// entry per key URL, holding the PEM weakly once it has arrived and
		/// the fetch in flight while it has not, so that callers arriving
		/// together share one request rather than each making their own.
		/// </summary>
		private static readonly ConcurrentDictionary<
			Uri,
			PublicKeyCacheEntry> _publicKeyCache =
			new ConcurrentDictionary<
				Uri,
				PublicKeyCacheEntry>();

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
			var entry = _publicKeyCache.GetOrAdd(
				u,
				static (u) => new PublicKeyCacheEntry());
			return entry.GetAsync(u).WaitAsync(cancellationToken);
        }

		/// <summary>
		/// The cache's view of one key URL. The PEM is held weakly so that
		/// memory pressure can reclaim it and a later caller fetches again,
		/// which is the behaviour the cache has always had. The fetch in
		/// flight is held strongly for as long as it is in flight, so that
		/// concurrent callers share it. A fetch that fails is never kept,
		/// so the next caller tries again rather than being handed the old
		/// failure.
		/// </summary>
		private sealed class PublicKeyCacheEntry
		{
			private readonly object _sync = new object();
			private WeakReference<string>? _publicKey;
			private Task<string>? _fetch;

			public Task<string> GetAsync(Uri u)
			{
				lock (_sync)
				{
					if (_publicKey != null &&
						_publicKey.TryGetTarget(out var publicKey))
					{
						return Task.FromResult(publicKey);
					}
					if (_fetch != null)
					{
						return _fetch;
					}
					var fetch = FetchAsync(u);
					// A fetch that has already finished has either stored
					// the key in this entry or failed, and neither is worth
					// keeping.
					if (fetch.IsCompleted == false)
					{
						_fetch = fetch;
					}
					return fetch;
				}
			}

			private async Task<string> FetchAsync(Uri u)
			{
				try
				{
					var publicKey = await new HttpClient(_handler)
						.GetStringAsync(u)
						.ConfigureAwait(false);
					lock (_sync)
					{
						_publicKey = new WeakReference<string>(publicKey);
					}
					return publicKey;
				}
				finally
				{
					// Whether the fetch succeeded or failed, it is no longer
					// in flight. Only one fetch is ever in flight for an
					// entry, so the one being cleared is this one.
					lock (_sync)
					{
						_fetch = null;
					}
				}
			}
		}
    }
}
