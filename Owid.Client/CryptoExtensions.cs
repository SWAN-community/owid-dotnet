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
		/// The most public keys held at once, across every creator. The
		/// cache is emptied rather than trimmed when it reaches this, which
		/// costs the keys still in use one request each as they are asked
		/// for again and keeps the bookkeeping to a count. The other ports
		/// hold the same number the same way.
		/// </summary>
		private const int MaximumCachedKeys = 1024;

		/// <summary>
		/// How far a creator's clock may run ahead of or behind this one's,
		/// in minutes. A minute closer to now than this, or later, is asked
		/// about rather than served from the cache, and is not held.
		/// </summary>
		/// <remarks>
		/// A creator reads a date later than its own now as now, and answers
		/// with the key in force now. Within this window this process cannot
		/// tell whether the creator read the minute as its past or as its
		/// present, so the answer says nothing certain about the minute. An
		/// identifier signed just after a rotation by a creator whose clock
		/// runs ahead would otherwise be served the old key from a span
		/// confirmed up to now, and would read as not matching until this
		/// clock caught up. Identifiers dated within the window are asked
		/// about once per minute per creator, as they always were, and every
		/// older identifier is served from the spans.
		/// </remarks>
		private const uint ClockDriftAllowanceMinutes = 15;

		/// <summary>
		/// One key a creator has answered with, and the span of minutes the
		/// creator has confirmed it was in force for.
		/// </summary>
		/// <remarks>
		/// A creator's key is in force from the start of its period until
		/// the next key starts, so a key the creator confirms at two minutes
		/// was in force at every minute between them. The span grows as the
		/// creator confirms the same key for more minutes, and an identifier
		/// dated inside it is verified without a request.
		/// </remarks>
		private sealed class HeldKey
		{
			public HeldKey(string pem, uint minute)
			{
				Pem = pem;
				First = minute;
				Last = minute;
			}

			/// <summary>
			/// The key in PEM form, as the creator served it.
			/// </summary>
			public string Pem { get; }

			/// <summary>
			/// The earliest minute the creator has confirmed the key for.
			/// </summary>
			public uint First { get; set; }

			/// <summary>
			/// The latest minute the creator has confirmed the key for.
			/// </summary>
			public uint Last { get; set; }

			/// <summary>
			/// Whether the minute lies within the confirmed span.
			/// </summary>
			public bool Covers(uint minute)
			{
				return First <= minute && minute <= Last;
			}
		}

		/// <summary>
		/// Guards <see cref="_publicKeyCache"/>, <see cref="_heldKeys"/>
		/// and <see cref="_inFlight"/>. Held across a few dictionary and
		/// list operations only, never across a request.
		/// </summary>
		private static readonly object _cacheLock = new object();

		/// <summary>
		/// Keys already fetched, by the creator's key end point, which is
		/// the key URL without its date. Each end point holds the keys the
		/// creator has answered with, each with the span of minutes the
		/// creator has confirmed it for.
		/// </summary>
		/// <remarks>
		/// The key URL carries the date of the OWID being verified, in
		/// minutes, and a creator's key changes on the order of a week.
		/// Keyed by the whole URL, as this cache once was, two identifiers
		/// signed a minute apart never shared an entry, so a hundred
		/// identifiers over a hundred minutes made a hundred requests for
		/// one key. Keyed by end point and span, an identifier dated between
		/// two minutes the creator has already answered for is verified
		/// without a request. The domain and the date come from the OWIDs
		/// presented to this process rather than from the process itself,
		/// so the number of keys held is bounded by
		/// <see cref="MaximumCachedKeys"/>.
		/// </remarks>
		private static readonly Dictionary<string, List<HeldKey>>
			_publicKeyCache = new Dictionary<string, List<HeldKey>>();

		/// <summary>
		/// How many keys are held across every end point.
		/// </summary>
		private static int _heldKeys;

		/// <summary>
		/// Requests under way, by the dated URL asked for, so that callers
		/// arriving together share one request rather than each making
		/// their own. An entry is removed when its request ends, whatever
		/// the outcome, so a failure is never handed to a later caller.
		/// </summary>
		private static readonly Dictionary<Uri, Task<string>> _inFlight =
			new Dictionary<Uri, Task<string>>();

		/// <summary>
		/// How many keys the cache holds, for the tests.
		/// </summary>
		internal static int CachedKeyCount
		{
			get
			{
				lock (_cacheLock)
				{
					return _heldKeys;
				}
			}
		}

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
		/// Get the public key PEM for the key URL. Answered from the cache
		/// where the creator has already confirmed a key for the minute the
		/// URL names, from a request already under way for the same URL
		/// where there is one, and otherwise by asking the creator.
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
			var endPoint = EndPointOf(u);
			var minute = MinuteOf(u);
			Task<string>? held;
			TaskCompletionSource<string>? source = null;
			lock (_cacheLock)
			{
				var pem = minute.HasValue
					? HeldPem(endPoint, minute.Value)
					: null;
				if (pem != null)
				{
					return Task.FromResult(pem);
				}
				if (_inFlight.TryGetValue(u, out held) == false)
				{
					// This caller is the one that adds the entry, so this
					// caller is the one that performs the request. Every
					// other caller arriving before it ends waits on the
					// task just added.
					source = new TaskCompletionSource<string>(
						TaskCreationOptions.RunContinuationsAsynchronously);
					held = source.Task;
					_inFlight[u] = held;
				}
			}
			if (source != null)
			{
				_ = FetchIntoAsync(u, endPoint, minute, source);
			}
			return held.WaitAsync(cancellationToken);
		}

		/// <summary>
		/// Perform the request for <paramref name="u"/> and put its outcome
		/// into <paramref name="source"/>, which is the task every caller
		/// for that URL is waiting on.
		/// </summary>
		/// <remarks>
		/// A key that arrives is held against the minute asked about before
		/// the request is forgotten, so a caller arriving between the two
		/// finds the key rather than starting a request of its own. A fetch
		/// that fails is only forgotten, so the next caller makes a fresh
		/// request rather than being handed the old failure.
		/// </remarks>
		private static async Task FetchIntoAsync(
			Uri u,
			string endPoint,
			uint? minute,
			TaskCompletionSource<string> source)
		{
			try
			{
				// disposeHandler is false because the handler is shared and
				// static. The constructor that takes a handler alone
				// disposes it with the client, so a caller who later wrapped
				// this in a using would take the handler away from every
				// other fetch, and with it the refusal to follow redirects.
				var publicKey = await new HttpClient(_handler, false)
					.GetStringAsync(u)
					.ConfigureAwait(false);
				lock (_cacheLock)
				{
					if (minute.HasValue)
					{
						Hold(endPoint, minute.Value, publicKey);
					}
					Forget(u, source.Task);
				}
				source.SetResult(publicKey);
			}
			catch (Exception e)
			{
				lock (_cacheLock)
				{
					Forget(u, source.Task);
				}
				source.SetException(e);
			}
		}

		/// <summary>
		/// Removes the request from those under way. The entry is matched
		/// on identity as well as URL, so a request that ends after the
		/// cache was emptied and a fresh request started for the same URL
		/// removes only itself and never the one that replaced it.
		/// </summary>
		private static void Forget(Uri u, Task<string> request)
		{
			if (_inFlight.TryGetValue(u, out var recorded)
				&& ReferenceEquals(recorded, request))
			{
				_inFlight.Remove(u);
			}
		}

		/// <summary>
		/// The key URL without its query, which names the scheme, the
		/// creator and the version, and so the key end point being asked.
		/// </summary>
		private static string EndPointOf(Uri u)
		{
			return u.GetLeftPart(UriPartial.Path);
		}

		/// <summary>
		/// The minute the cache reads the URL as asking about, or null where
		/// the cache must not be used for the request.
		/// </summary>
		/// <remarks>
		/// The date parameter where the URL carries one and it is at least
		/// <see cref="ClockDriftAllowanceMinutes"/> behind now. A request
		/// without a date asks for the key in force now, and one dated
		/// within the allowance, or later, may be read by the creator as its
		/// present rather than as the minute named, so neither is served
		/// from the cache nor held in it.
		/// </remarks>
		private static uint? MinuteOf(Uri u)
		{
			var now = (uint)Math.Min(
				(DateTime.UtcNow - Constants.BaseDate).TotalMinutes,
				uint.MaxValue);
			foreach (var pair in u.Query.TrimStart('?').Split('&'))
			{
				if (pair.StartsWith("date=", StringComparison.Ordinal)
					&& uint.TryParse(pair.Substring(5), out var minute)
					&& now >= ClockDriftAllowanceMinutes
					&& minute <= now - ClockDriftAllowanceMinutes)
				{
					return minute;
				}
			}
			return null;
		}

		/// <summary>
		/// The key held for the end point whose confirmed span covers the
		/// minute, or null where no held key does. Called under the lock.
		/// </summary>
		private static string? HeldPem(string endPoint, uint minute)
		{
			if (_publicKeyCache.TryGetValue(endPoint, out var keys))
			{
				foreach (var key in keys)
				{
					if (key.Covers(minute))
					{
						return key.Pem;
					}
				}
			}
			return null;
		}

		/// <summary>
		/// Records that the creator answered the minute with the key. Called
		/// under the lock.
		/// </summary>
		/// <remarks>
		/// A key already held for the end point has its span widened to take
		/// in the minute. A key not held before is added, emptying the cache
		/// first when it is full, because the domains and dates asked about
		/// come from the OWIDs presented to this process and the cache must
		/// not grow on their input.
		/// </remarks>
		private static void Hold(string endPoint, uint minute, string pem)
		{
			if (_publicKeyCache.TryGetValue(endPoint, out var keys))
			{
				foreach (var key in keys)
				{
					if (key.Pem == pem && Widen(keys, key, minute))
					{
						return;
					}
				}
			}
			else
			{
				keys = null;
			}
			if (_heldKeys >= MaximumCachedKeys)
			{
				_publicKeyCache.Clear();
				_heldKeys = 0;
				keys = null;
			}
			if (keys == null)
			{
				keys = new List<HeldKey>();
				_publicKeyCache[endPoint] = keys;
			}
			keys.Add(new HeldKey(pem, minute));
			_heldKeys++;
		}

		/// <summary>
		/// Widens the span of a held key to take in the minute, and says
		/// whether the minute is now within it.
		/// </summary>
		/// <remarks>
		/// The span is not widened across a minute the creator has answered
		/// with another key for, because that would mean the creator had
		/// gone back to a key it had left, and the minutes between the two
		/// spans are then not this key's to claim. The key is held again as
		/// a separate span instead.
		/// </remarks>
		private static bool Widen(List<HeldKey> keys, HeldKey key, uint minute)
		{
			if (key.Covers(minute))
			{
				return true;
			}
			var from = Math.Min(minute, key.First);
			var to = Math.Max(minute, key.Last);
			foreach (var other in keys)
			{
				if (ReferenceEquals(other, key) == false
					&& other.Last > from
					&& other.First < to)
				{
					return false;
				}
			}
			if (minute < key.First)
			{
				key.First = minute;
			}
			else
			{
				key.Last = minute;
			}
			return true;
		}

		/// <summary>
		/// Empty the public key cache, so that the next verification of any
		/// OWID fetches the creator's key again, and forget the requests
		/// under way so that the next caller for any key starts a request
		/// of its own. A request already under way is not stopped, and the
		/// callers waiting on it still receive its answer. This is how a
		/// long running process drops a key it has learned it should no
		/// longer trust, after a creator rotates its key following a
		/// compromise. The other ports offer the same.
		/// </summary>
		public static void ClearPublicKeyCache()
		{
			lock (_cacheLock)
			{
				_publicKeyCache.Clear();
				_heldKeys = 0;
				_inFlight.Clear();
			}
		}
	}
}
