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
using System.Text.Json;
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
		/// in minutes.
		/// </summary>
		/// <remarks>
		/// It is used in two places. A creator that does not state the end
		/// of the span of the key it answers with reads a date later than
		/// its own now as now, so within this window of now this process
		/// cannot tell whether the creator read the minute as its past or
		/// as its present, and nothing learned from such an answer is held
		/// or served. And a creator's signing machines may not agree with
		/// the creator's own schedule to the minute, so an identifier dated
		/// within this window of an edge of the span the creator stated for
		/// a key that does not verify under that key is checked against the
		/// key for the minute just beyond that edge before it is reported as
		/// not matching.
		/// </remarks>
		private const uint ClockDriftAllowanceMinutes = 15;

		/// <summary>
		/// One key a creator has answered with, and the span of minutes the
		/// key is known to cover.
		/// </summary>
		/// <remarks>
		/// A creator's key is in force from the start of its period until
		/// the next key starts, so a key the creator confirms at two minutes
		/// was in force at every minute between them. Where the creator
		/// stated the span in its answer the span is explicit and complete,
		/// and an identifier dated anywhere inside it is verified without a
		/// request. Otherwise the span grows as the creator confirms the same
		/// key for more minutes.
		/// </remarks>
		private sealed class HeldKey
		{
			public HeldKey(string pem, uint first, uint last, bool explicitSpan, bool openEnded)
			{
				Pem = pem;
				First = first;
				Last = last;
				Explicit = explicitSpan;
				OpenEnded = openEnded;
			}

			/// <summary>
			/// The key in PEM form, as the creator served it.
			/// </summary>
			public string Pem { get; }

			/// <summary>
			/// The earliest minute the key is known to cover.
			/// </summary>
			public uint First { get; set; }

			/// <summary>
			/// The latest minute the key is known to cover.
			/// </summary>
			public uint Last { get; set; }

			/// <summary>
			/// Whether the creator stated the whole span itself.
			/// </summary>
			public bool Explicit { get; set; }

			/// <summary>
			/// Whether the creator stated the start of the span and no end,
			/// so that as far as the creator has said the key is in force
			/// until further notice, whatever this cache holds it for.
			/// </summary>
			public bool OpenEnded { get; set; }

			/// <summary>
			/// Whether the minute lies within the known span.
			/// </summary>
			public bool Covers(uint minute)
			{
				return First <= minute && minute <= Last;
			}
		}

		/// <summary>
		/// What the cache or a fetch answers with. The key, and where it is
		/// stated one, the span of minutes the creator says the key covers,
		/// so that a caller can tell whether the identifier it is checking
		/// sits near an edge of the span, or outside it altogether. A span
		/// stated with a start and no end runs to the last minute there is.
		/// </summary>
		internal readonly struct KeyAnswer
		{
			public KeyAnswer(string pem, uint first, uint last, bool known)
			{
				Pem = pem;
				First = first;
				Last = last;
				Known = known;
			}

			/// <summary>The key in PEM form.</summary>
			public string Pem { get; }

			/// <summary>The first minute the creator says the key covers.</summary>
			public uint First { get; }

			/// <summary>The last minute the creator says the key covers.</summary>
			public uint Last { get; }

			/// <summary>Whether the creator stated a span at all.</summary>
			public bool Known { get; }

			/// <summary>Whether the minute lies within the stated span.</summary>
			public bool Covers(uint minute)
			{
				return Known && First <= minute && minute <= Last;
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
		/// creator has answered with, each with the span of minutes it is
		/// known to cover.
		/// </summary>
		/// <remarks>
		/// The key URL carries the date of the OWID being verified, in
		/// minutes, and a creator's key changes on the order of a week.
		/// Keyed by end point and span rather than by the whole URL, an identifier dated inside
		/// a span the creator has stated or confirmed is verified without a
		/// request. The domain and the date come from the OWIDs presented to
		/// this process rather than from the process itself, so the number
		/// of keys held is bounded by <see cref="MaximumCachedKeys"/>.
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
		private static readonly Dictionary<Uri, Task<KeyAnswer>> _inFlight =
			new Dictionary<Uri, Task<KeyAnswer>>();

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
			return await owid.VerifyAtAsync(
				KeyEndPointFor(owid, "https"),
				others,
				cancellationToken).ConfigureAwait(false);
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
        /// reject good identifiers during an outage. 
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
		/// The creator's key end point for the OWID over the scheme given,
		/// being the key URL without its query.
		/// </summary>
		private static string KeyEndPointFor(Model.Owid owid, string scheme)
		{
			var u = new UriBuilder(scheme, owid.Domain)
			{
				Path = @$"/owid/api/v{(byte)owid.Version}/public-key"
			};
			return u.Uri.GetLeftPart(UriPartial.Path);
		}

		/// <summary>
		/// The key URL asking the end point for the key in force at the
		/// minute, or for the key in force now where there is no minute.
		/// </summary>
		/// <remarks>
		/// Sending the OWID's own date lets a creator that rotates keys
		/// return the key that was current when the OWID was signed, so
		/// OWIDs created before a rotation still verify. Creators that do not
		/// support dated lookup ignore it and return the current key.
		/// </remarks>
		private static Uri KeyUriFor(string endPoint, uint? minute)
		{
			return new Uri(minute.HasValue
				? endPoint + "?format=pkcs&date=" + minute.Value
				: endPoint + "?format=pkcs");
		}

		/// <summary>
		/// The OWID's date as minutes since the base date, or null where it
		/// is before the base date and cannot be counted.
		/// </summary>
		private static uint? MinuteOf(Model.Owid owid)
		{
			return owid.Date >= Constants.BaseDate
				? (uint)(owid.Date - Constants.BaseDate).TotalMinutes
				: null;
		}

		/// <summary>
		/// The ECDsa provider for the key in PEM form.
		/// </summary>
		private static ECDsa ImportKey(string publicKeyPem)
		{
			// Reject an empty or whitespace PEM with a clear message rather
			// than relying on the opaque exception thrown by ImportFromPem.
			if (string.IsNullOrWhiteSpace(publicKeyPem))
			{
				throw new ArgumentException("public key PEM is empty");
			}
			var key = ECDsa.Create();
			key.ImportFromPem(publicKeyPem);
			return key;
		}

		/// <summary>
		/// Says whether the signature is genuine using the key the creator's
		/// domain serves for the OWID's own date, or why that could not be
		/// decided.
		/// </summary>
		/// <remarks>
		/// A creator that cannot be reached, or that answers with something
		/// other than a key, or whose own statement of the span puts the
		/// OWID's date outside the key it answered with, leaves the
		/// signature unjudged and is reported as such rather than as a
		/// forgery. See <see cref="SignatureStatus(Model.Owid, ECDsa, Model.Owid[])"/>
		/// for the answers about the signature itself.
		/// </remarks>
		/// <param name="owid"></param>
		/// <param name="others"></param>
		/// <param name="cancellationToken">
		/// Ends this caller's wait for the key. See
		/// <see cref="GetPublicKeyAsync(Uri, CancellationToken)"/> for what
		/// that does and does not cancel.
		/// </param>
		public static async Task<OwidSignatureStatus> SignatureStatusAsync(
			this Model.Owid owid,
			Model.Owid[] others,
			CancellationToken cancellationToken = default)
		{
			try
			{
				return await owid.SignatureStatusAtAsync(
					KeyEndPointFor(owid, "https"),
					others,
					cancellationToken).ConfigureAwait(false);
			}
			catch (HttpRequestException)
			{
				return OwidSignatureStatus.KeyUnavailable;
			}
			catch (Exception e) when (
				e is ArgumentException ||
				e is CryptographicException ||
				e is FormatException)
			{
				return OwidSignatureStatus.InvalidKey;
			}
		}

		/// <summary>
		/// Says whether the signature is genuine using the key the creator's
		/// domain serves for the OWID's own date, or why that could not be
		/// decided. See
		/// <see cref="SignatureStatusAsync(Model.Owid, Model.Owid[], CancellationToken)"/>.
		/// </summary>
		public static Task<OwidSignatureStatus> SignatureStatusAsync(
			this Model.Owid owid,
			CancellationToken cancellationToken = default)
		{
			return owid.SignatureStatusAsync(Constants.Empty, cancellationToken);
		}

		/// <summary>
		/// Verify the OWID against the key its creator's end point serves
		/// for the OWID's own date, trying the neighbouring key where the
		/// signature fails within the clock drift allowance of an edge of
		/// the span the creator stated for the key.
		/// </summary>
		/// <remarks>
		/// Internal rather than private so the test project can point it at
		/// a stand in end point by URL, since the domain an OWID carries
		/// cannot name a port.
		/// </remarks>
		/// <exception cref="InvalidOperationException">
		/// The creator's own statement of the span puts the OWID's date
		/// outside the key it answered with, so the signature could not be
		/// checked and false would have read as a forgery.
		/// </exception>
		internal static async Task<bool> VerifyAtAsync(
			this Model.Owid owid,
			string endPoint,
			Model.Owid[] others,
			CancellationToken cancellationToken)
		{
			var status = await owid.SignatureStatusAtAsync(
				endPoint, others, cancellationToken).ConfigureAwait(false);
			if (status == OwidSignatureStatus.KeyUnavailable)
			{
				throw new InvalidOperationException(
					"the creator states that the key it answered with was not in force at the OWID's date, so the signature could not be checked");
			}
			return status == OwidSignatureStatus.SignatureValid;
		}

		/// <summary>
		/// The status of the signature under the key the end point serves
		/// for the OWID's own date, or under the neighbouring key where the
		/// date is within the clock drift allowance of an edge of the span
		/// the creator stated. A key the creator says was not in force at
		/// the OWID's date proves nothing about the identifier, so where
		/// nothing verifies under such a key the answer is that the key is
		/// unavailable and not that the signature does not match.
		/// </summary>
		internal static async Task<OwidSignatureStatus> SignatureStatusAtAsync(
			this Model.Owid owid,
			string endPoint,
			Model.Owid[] others,
			CancellationToken cancellationToken)
		{
			var minute = MinuteOf(owid);
			var answer = await GetKeyAsync(
				KeyUriFor(endPoint, minute),
				cancellationToken).ConfigureAwait(false);
			using (var crypto = ImportKey(answer.Pem))
			{
				var status = owid.SignatureStatus(crypto, others);
				if (status != OwidSignatureStatus.SignatureInvalid)
				{
					return status;
				}
			}
			if (minute == null)
			{
				return OwidSignatureStatus.SignatureInvalid;
			}
			if (await NeighbourVerifiesAsync(
				owid, minute.Value, endPoint, answer, others, cancellationToken)
				.ConfigureAwait(false))
			{
				return OwidSignatureStatus.SignatureValid;
			}
			return answer.Known && answer.Covers(minute.Value) == false
				? OwidSignatureStatus.KeyUnavailable
				: OwidSignatureStatus.SignatureInvalid;
		}

		/// <summary>
		/// Whether a key neighbouring the one the OWID's own minute selected
		/// verifies the signature instead.
		/// </summary>
		/// <remarks>
		/// A creator's signing machines may not agree with its own schedule
		/// to the minute, so an identifier dated just after a key started
		/// may have been signed with the key before it, and one dated just
		/// before may have been signed with the key after. Where the
		/// signature does not verify under the key selected and the OWID's
		/// minute is within the clock drift allowance of an edge of the span
		/// the creator stated for that key, the key for the minute just
		/// beyond that edge is asked for and tried. A key already held for
		/// that minute is not asked for again, and a neighbour that turns
		/// out to be the same key is not tried again. A creator that stated
		/// no span has one key and no schedule, so there is no neighbour to
		/// try. This costs at most two more requests, and only for a
		/// signature that has already failed.
		/// </remarks>
		private static async Task<bool> NeighbourVerifiesAsync(
			Model.Owid owid,
			uint minute,
			string endPoint,
			KeyAnswer tried,
			Model.Owid[] others,
			CancellationToken cancellationToken)
		{
			if (tried.Known == false)
			{
				return false;
			}
			var beyond = new List<uint>(2);
			if (tried.First > 0 && NearEdge(minute, tried.First))
			{
				beyond.Add(tried.First - 1);
			}
			if (tried.Last < uint.MaxValue && NearEdge(minute, tried.Last))
			{
				beyond.Add(tried.Last + 1);
			}
			foreach (var at in beyond)
			{
				KeyAnswer neighbour;
				try
				{
					neighbour = await GetKeyAsync(
						KeyUriFor(endPoint, at),
						cancellationToken).ConfigureAwait(false);
				}
				catch (Exception e) when (e is not OperationCanceledException)
				{
					// A neighbour that cannot be obtained leaves the failure
					// under the selected key standing.
					continue;
				}
				if (neighbour.Pem == tried.Pem)
				{
					continue;
				}
				using (var crypto = ImportKey(neighbour.Pem))
				{
					if (owid.Verify(crypto, others))
					{
						return true;
					}
				}
			}
			return false;
		}

		/// <summary>
		/// Whether the minute is no further from the edge minute than the
		/// clocks of a creator's signing machines are allowed to differ
		/// from its schedule.
		/// </summary>
		private static bool NearEdge(uint minute, uint edge)
		{
			var apart = minute > edge ? minute - edge : edge - minute;
			return apart <= ClockDriftAllowanceMinutes;
		}

		/// <summary>
		/// Get the public key PEM for the key URL. See
		/// <see cref="GetKeyAsync(Uri, CancellationToken)"/>.
		/// </summary>
		/// <param name="u"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		// Internal rather than private so the test project can point it
		// at a stand in end point by URL, since the domain an OWID carries
		// cannot name a port.
		internal static async Task<string> GetPublicKeyAsync(
			Uri u,
			CancellationToken cancellationToken = default)
		{
			var answer = await GetKeyAsync(u, cancellationToken)
				.ConfigureAwait(false);
			return answer.Pem;
		}

		/// <summary>
		/// Get the key for the key URL, with the span it is known to cover.
		/// Answered from the cache where a held key is known to cover the
		/// minute the URL names, from a request already under way for the
		/// same URL where there is one, and otherwise by asking the creator.
		/// </summary>
		/// <remarks>
		/// The token ends this caller's wait, not the shared request. A
		/// request one caller started is usually the request every other
		/// caller for the same key is waiting on, so letting one caller
		/// abandon the request for all of them would turn one timeout into
		/// many. The request runs to completion and the next caller finds
		/// the key in the cache.
		/// </remarks>
		internal static Task<KeyAnswer> GetKeyAsync(
			Uri u,
			CancellationToken cancellationToken = default)
		{
			var endPoint = EndPointOf(u);
			Task<KeyAnswer>? held;
			TaskCompletionSource<KeyAnswer>? source = null;
			lock (_cacheLock)
			{
				var cached = HeldFor(endPoint, u);
				if (cached != null)
				{
					return Task.FromResult(cached.Value);
				}
				if (_inFlight.TryGetValue(u, out held) == false)
				{
					// This caller is the one that adds the entry, so this
					// caller is the one that performs the request. Every
					// other caller arriving before it ends waits on the
					// task just added.
					source = new TaskCompletionSource<KeyAnswer>(
						TaskCreationOptions.RunContinuationsAsynchronously);
					held = source.Task;
					_inFlight[u] = held;
				}
			}
			if (source != null)
			{
				_ = FetchIntoAsync(u, endPoint, source);
			}
			return held.WaitAsync(cancellationToken);
		}

		/// <summary>
		/// Perform the request for <paramref name="u"/> and put its outcome
		/// into <paramref name="source"/>, which is the task every caller
		/// for that URL is waiting on.
		/// </summary>
		/// <remarks>
		/// The answer is the JSON form, which carries the moments the key is
		/// valid from and to as well as the key, so the whole span is held
		/// from that one answer. An answer in any other form, the PEM alone
		/// among them, is refused. A key that arrives is held before the request
		/// is forgotten, so a caller arriving between the two finds the key
		/// rather than starting a request of its own. A fetch that fails is
		/// only forgotten, so the next caller makes a fresh request rather
		/// than being handed the old failure.
		/// </remarks>
		private static async Task FetchIntoAsync(
			Uri u,
			string endPoint,
			TaskCompletionSource<KeyAnswer> source)
		{
			try
			{
				// disposeHandler is false because the handler is shared and
				// static. The constructor that takes a handler alone
				// disposes it with the client, so a caller who later wrapped
				// this in a using would take the handler away from every
				// other fetch, and with it the refusal to follow redirects.
				var body = await new HttpClient(_handler, false)
					.GetStringAsync(u)
					.ConfigureAwait(false);
				var (pem, start, end) = ReadKeyBody(body);
				KeyAnswer answer;
				lock (_cacheLock)
				{
					answer = Hold(endPoint, u, pem, start, end);
					Forget(u, source.Task);
				}
				source.SetResult(answer);
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
		/// Reads a public key answer, returning the PEM and the span in
		/// minutes since the base date. The end is the minute the next key
		/// starts. Either is null where the answer does not state it.
		/// </summary>
		/// <exception cref="ArgumentException">
		/// The answer is not the JSON form the specification requires, the
		/// PEM alone among the other forms, or fails the checks a creator
		/// applies before sending it.
		/// </exception>
		private static (string pem, uint? start, uint? end) ReadKeyBody(string body)
		{
			PublicKeyResponse? answer;
			try
			{
				answer = JsonSerializer.Deserialize<PublicKeyResponse>(body);
			}
			catch (JsonException e)
			{
				throw new ArgumentException(
					"the public key answer is not the JSON form the specification requires", e);
			}
			if (answer == null)
			{
				throw new ArgumentException("the public key answer holds no key");
			}
			try
			{
				answer.Validate(null);
			}
			catch (InvalidOperationException e)
			{
				throw new ArgumentException(e.Message, e);
			}
			return (answer.PublicKeySPKI, MinutesOf(answer.ValidFrom), MinutesOf(answer.ValidTo));
		}

		/// <summary>
		/// The moment as minutes since the base date, or null where there is
		/// no moment or it is before the count begins.
		/// </summary>
		private static uint? MinutesOf(DateTime? moment)
		{
			if (moment == null)
			{
				return null;
			}
			var utc = moment.Value.Kind == DateTimeKind.Local
				? moment.Value.ToUniversalTime()
				: DateTime.SpecifyKind(moment.Value, DateTimeKind.Utc);
			if (utc < Constants.BaseDate)
			{
				return null;
			}
			var minutes = (utc - Constants.BaseDate).TotalMinutes;
			return minutes >= uint.MaxValue ? uint.MaxValue : (uint)minutes;
		}

		/// <summary>
		/// Removes the request from those under way. The entry is matched
		/// on identity as well as URL, so a request that ends after the
		/// cache was emptied and a fresh request started for the same URL
		/// removes only itself and never the one that replaced it.
		/// </summary>
		private static void Forget(Uri u, Task<KeyAnswer> request)
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
		/// The minute the URL asks about, and whether it lies within the
		/// clock drift allowance of now or later, which is a minute a creator
		/// that does not state its spans may have read as its present rather
		/// than as the minute named. Returns false where the URL names no
		/// minute.
		/// </summary>
		private static bool TryMinuteOf(Uri u, out uint minute, out bool recent)
		{
			var now = (uint)Math.Min(
				(DateTime.UtcNow - Constants.BaseDate).TotalMinutes,
				uint.MaxValue);
			foreach (var pair in u.Query.TrimStart('?').Split('&'))
			{
				if (pair.StartsWith("date=", StringComparison.Ordinal)
					&& uint.TryParse(pair.Substring(5), out minute))
				{
					recent = now < ClockDriftAllowanceMinutes
						|| minute > now - ClockDriftAllowanceMinutes;
					return true;
				}
			}
			minute = 0;
			recent = false;
			return false;
		}

		/// <summary>
		/// The key held for the end point that is known to cover the minute
		/// the URL asks about, or null where none is. Called under the lock.
		/// </summary>
		/// <remarks>
		/// A minute within the drift allowance of now is only served where
		/// the creator itself stated the span, because a span confirmed
		/// minute by minute says nothing certain about such a minute.
		/// </remarks>
		private static KeyAnswer? HeldFor(string endPoint, Uri u)
		{
			if (TryMinuteOf(u, out var minute, out var recent) == false)
			{
				return null;
			}
			if (_publicKeyCache.TryGetValue(endPoint, out var keys))
			{
				foreach (var key in keys)
				{
					if (key.Covers(minute) && (key.Explicit || recent == false))
					{
						return StatedFor(key);
					}
				}
			}
			return null;
		}

		/// <summary>
		/// The span the creator stated for a held key, which is the whole
		/// held span where the creator stated it, runs to the last minute
		/// there is where the creator stated a start and no end, and is
		/// nothing where the creator stated no span.
		/// </summary>
		private static KeyAnswer StatedFor(HeldKey key)
		{
			if (key.Explicit)
			{
				return new KeyAnswer(key.Pem, key.First, key.Last, true);
			}
			if (key.OpenEnded)
			{
				return new KeyAnswer(key.Pem, key.First, uint.MaxValue, true);
			}
			return new KeyAnswer(key.Pem, 0, 0, false);
		}

		/// <summary>
		/// The span the creator stated in its answer. See
		/// <see cref="StatedFor(HeldKey)"/>.
		/// </summary>
		private static KeyAnswer Stated(string pem, uint? start, uint? end)
		{
			if (start == null)
			{
				return new KeyAnswer(pem, 0, 0, false);
			}
			if (end != null && end.Value > start.Value)
			{
				return new KeyAnswer(pem, start.Value, end.Value - 1, true);
			}
			return new KeyAnswer(pem, start.Value, uint.MaxValue, true);
		}

		/// <summary>
		/// Records the creator's answer to the URL, being the key and, where
		/// the creator stated it, the span the key covers as the minute it
		/// came into force and the minute the next key starts. Returns the
		/// key with the span the creator stated for it. Called under the
		/// lock.
		/// </summary>
		/// <remarks>
		/// With both the start and the end the whole span is held as the
		/// creator's own statement. With the start alone the key is held
		/// from the start up to the drift allowance behind now, because no
		/// later key can have started before then. With neither the minute
		/// asked about is held on its own, as long as it is not within the
		/// drift allowance of now. A key already held for the end point has
		/// its span widened to take in the new one. A key not held before is
		/// added, emptying the cache first when it is full, because the
		/// cache must not grow on the input of whoever presents the OWIDs.
		/// </remarks>
		private static KeyAnswer Hold(
			string endPoint,
			Uri u,
			string pem,
			uint? start,
			uint? end)
		{
			var stated = Stated(pem, start, end);
			var dated = TryMinuteOf(u, out var minute, out var recent);
			uint first;
			uint last;
			var explicitSpan = false;
			var openEnded = false;
			if (start != null && end != null && end.Value > start.Value)
			{
				first = start.Value;
				last = end.Value - 1;
				explicitSpan = true;
			}
			else if (start != null)
			{
				var now = (uint)Math.Min(
					(DateTime.UtcNow - Constants.BaseDate).TotalMinutes,
					uint.MaxValue);
				first = start.Value;
				last = now >= ClockDriftAllowanceMinutes
					&& now - ClockDriftAllowanceMinutes > first
					? now - ClockDriftAllowanceMinutes
					: first;
				openEnded = true;
			}
			else if (dated && recent == false)
			{
				first = minute;
				last = minute;
			}
			else
			{
				return stated;
			}
			_publicKeyCache.TryGetValue(endPoint, out var keys);
			if (keys != null)
			{
				foreach (var key in keys)
				{
					if (key.Pem == pem)
					{
						if (Widen(keys, key, first, last))
						{
							key.Explicit = key.Explicit || explicitSpan;
							key.OpenEnded = key.Explicit == false
								&& (key.OpenEnded || openEnded);
						}
						// Where the span was not widened the creator has
						// answered with another key inside it before, which
						// it does not do unless it went back to a key it had
						// left, and nothing more is held about this key.
						return stated;
					}
				}
				foreach (var other in keys)
				{
					if (other.Last >= first && other.First <= last)
					{
						return stated;
					}
				}
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
			keys.Add(new HeldKey(pem, first, last, explicitSpan, openEnded));
			_heldKeys++;
			return stated;
		}

		/// <summary>
		/// Widens the span of a held key to take in the span given, and says
		/// whether it did.
		/// </summary>
		/// <remarks>
		/// The span is not widened across a minute the creator has answered
		/// with another key for, because that would mean the creator had
		/// gone back to a key it had left, and the minutes between the two
		/// spans are then not this key's to claim.
		/// </remarks>
		private static bool Widen(List<HeldKey> keys, HeldKey key, uint first, uint last)
		{
			first = Math.Min(first, key.First);
			last = Math.Max(last, key.Last);
			foreach (var other in keys)
			{
				if (ReferenceEquals(other, key) == false
					&& other.Last >= first
					&& other.First <= last)
				{
					return false;
				}
			}
			key.First = first;
			key.Last = last;
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
