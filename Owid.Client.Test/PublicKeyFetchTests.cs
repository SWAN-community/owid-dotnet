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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Owid.Client.Test
{
    /// <summary>
    /// The fetch of a creator's public key is asynchronous all the way down,
    /// shares one request between callers that arrive together, never keeps
    /// a failed request in the cache, and holds each key against the span of
    /// minutes the creator has confirmed it for rather than against the
    /// minute of one identifier.
    /// </summary>
    [TestClass]
    public class PublicKeyFetchTests
    {
        /// <summary>
        /// A genuine public key for the stand in creator to answer with,
        /// because an answer is checked before it is sent and a key that
        /// cannot be read would be refused.
        /// </summary>
        private static readonly string Pem = FreshPem();

        /// <summary>
        /// The public key of a newly made key pair, in PEM form.
        /// </summary>
        private static string FreshPem()
        {
            using var crypto = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            return new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", crypto.ExportSubjectPublicKeyInfo()));
        }

        /// <summary>
        /// The minute the fixture identifier used across the ports was
        /// created at, 2026-09-04T00:00:00Z counted from 2020-01-01. In the
        /// past, so the cache reads it as itself rather than as now.
        /// </summary>
        private const uint Minute = 3_510_720;

        /// <summary>
        /// The minutes in a week, which is how often the 51Degrees cloud
        /// rotates its key.
        /// </summary>
        private const uint Week = 7 * 24 * 60;

        /// <summary>
        /// A key URL on the stand in end point for the minute given.
        /// </summary>
        private static Uri Dated(string prefix, uint minute)
        {
            return new Uri(prefix + "owid/api/v3/public-key?format=pkcs&date=" + minute);
        }

        /// <summary>
        /// The minute the cache reads now as, counted the way the library
        /// counts it.
        /// </summary>
        private static uint Now()
        {
            var baseDate = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return (uint)(DateTime.UtcNow - baseDate).TotalMinutes;
        }

        /// <summary>
        /// The value of the date parameter of a request, or null where it
        /// carries none.
        /// </summary>
        private static uint? DateOf(HttpListenerRequest request)
        {
            var date = request.QueryString["date"];
            return date == null ? null : uint.Parse(date);
        }

        /// <summary>
        /// Serves every request the listener receives with the handler's
        /// verdict, until stopped. The handler returns the status code to
        /// send, and a 200 carries the JSON answer for the PEM the second
        /// handler gives for the request, or the fixed PEM where there is
        /// none, with no moments stated, as a creator with one key and no
        /// schedule answers.
        /// </summary>
        private static Task Serve(
            HttpListener listener,
            CancellationToken stop,
            Func<Task<int>> handler,
            Func<HttpListenerRequest, string>? pemFor = null)
        {
            return Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await listener.GetContextAsync(); }
                    catch (Exception) { return; }
                    try
                    {
                        var status = await handler();
                        context.Response.StatusCode = status;
                        if (status == 200)
                        {
                            var pem = pemFor == null
                                ? Pem
                                : pemFor(context.Request);
                            // The JSON form with no moments, as a creator
                            // with one key and no schedule answers.
                            var bytes = Encoding.UTF8.GetBytes(
                                System.Text.Json.JsonSerializer.Serialize(
                                    new Model.PublicKeyResponse { PublicKey = pem }));
                            context.Response.ContentType = "application/json";
                            await context.Response.OutputStream.WriteAsync(
                                bytes, 0, bytes.Length);
                        }
                        context.Response.Close();
                    }
                    catch (Exception)
                    {
                        // A test that has finished stops its listener,
                        // which can happen while a response is still
                        // being written to a caller that has already
                        // gone away. Nothing here is under test, so the
                        // loop ends quietly rather than faulting the
                        // serving task and failing the test that is
                        // tidying up after itself.
                        return;
                    }
                }
            });
        }

        /// <summary>
        /// Two callers asking for the same key while the first request is
        /// still in flight share that request. A third caller after it has
        /// completed is answered from the cache.
        /// </summary>
        [TestMethod]
        public async Task ConcurrentCallersShareOneRequest()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            var firstRequestArrived = new TaskCompletionSource<bool>();
            var release = new TaskCompletionSource<bool>();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, async () =>
            {
                Interlocked.Increment(ref hits);
                firstRequestArrived.TrySetResult(true);
                // Hold the response until the test has issued the second
                // call, so both are in flight against one request.
                await release.Task;
                return 200;
            });

            try
            {
                var url = Dated(prefix, Minute);
                var first = CryptoExtensions.GetPublicKeyAsync(url);
                await firstRequestArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));
                var second = CryptoExtensions.GetPublicKeyAsync(url);
                Assert.IsFalse(first.IsCompleted, "the first call is still waiting");
                Assert.IsFalse(second.IsCompleted, "the second call is still waiting");

                release.SetResult(true);
                var keys = await Task.WhenAll(first, second)
                    .WaitAsync(TimeSpan.FromSeconds(5));
                Assert.AreEqual(Pem, keys[0]);
                Assert.AreEqual(Pem, keys[1]);
                Assert.AreEqual(1, hits,
                    "the second caller joined the first request rather than "
                    + "making its own");

                var third = await CryptoExtensions.GetPublicKeyAsync(url)
                    .WaitAsync(TimeSpan.FromSeconds(5));
                Assert.AreEqual(Pem, third);
                Assert.AreEqual(1, hits, "a later caller is answered from the cache");
            }
            finally
            {
                release.TrySetResult(true);
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A request that fails is not kept, so the next caller tries again
        /// rather than being handed the earlier failure.
        /// </summary>
        [TestMethod]
        public async Task AFailedRequestIsNotCached()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () =>
            {
                // The first request fails, every later one succeeds.
                var hit = Interlocked.Increment(ref hits);
                return Task.FromResult(hit == 1 ? 500 : 200);
            });

            try
            {
                var url = Dated(prefix, Minute);
                HttpRequestException? failed = null;
                try
                {
                    await CryptoExtensions.GetPublicKeyAsync(url)
                        .WaitAsync(TimeSpan.FromSeconds(5));
                    Assert.Fail("a 500 must not yield a key");
                }
                catch (HttpRequestException thrown)
                {
                    failed = thrown;
                }
                Assert.AreEqual(
                    HttpStatusCode.InternalServerError, failed!.StatusCode);

                var key = await CryptoExtensions.GetPublicKeyAsync(url)
                    .WaitAsync(TimeSpan.FromSeconds(5));
                Assert.AreEqual(Pem, key);
                Assert.AreEqual(2, hits, "the second caller made a fresh request");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A caller whose token is cancelled stops waiting, and the wait
        /// ends with the cancellation rather than with a key.
        /// </summary>
        [TestMethod]
        public async Task ACancelledCallerStopsWaiting()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var release = new TaskCompletionSource<bool>();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, async () =>
            {
                await release.Task;
                return 200;
            });

            try
            {
                var url = Dated(prefix, Minute);
                using var caller = new CancellationTokenSource();
                var waiting = CryptoExtensions.GetPublicKeyAsync(url, caller.Token);
                caller.Cancel();
                await Assert.ThrowsExactlyAsync<TaskCanceledException>(
                    () => waiting.WaitAsync(TimeSpan.FromSeconds(5)));
            }
            finally
            {
                release.TrySetResult(true);
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// Many callers arriving at once for a key none of them finds in the
        /// cache still make one request between them.
        /// </summary>
        /// <remarks>
        /// The test above lets the first caller record its request before
        /// the second arrives, so it never exercises the contention itself.
        /// Here every caller is released together and all of them miss the
        /// cache, so all of them reach the record of requests under way at
        /// once. Exactly one may go on to perform the request. Replace the
        /// lookup of the requests under way with one that never finds
        /// anything and this test fails reporting many requests.
        /// </remarks>
        [TestMethod]
        public async Task ManyCallersArrivingTogetherMakeOneRequest()
        {
            const int callers = 64;
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            var release = new TaskCompletionSource<bool>();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, async () =>
            {
                Interlocked.Increment(ref hits);
                // Held so that every caller is still waiting, and a second
                // request would be counted before the first has answered.
                await release.Task;
                return 200;
            });

            try
            {
                var url = Dated(prefix, Minute);
                var start = new TaskCompletionSource<bool>();
                var waiting = new Task<string>[callers];
                for (var i = 0; i < callers; i++)
                {
                    waiting[i] = Task.Run(async () =>
                    {
                        await start.Task;
                        return await CryptoExtensions.GetPublicKeyAsync(url);
                    });
                }

                // Every caller goes at the same moment.
                start.SetResult(true);
                release.SetResult(true);
                var keys = await Task.WhenAll(waiting)
                    .WaitAsync(TimeSpan.FromSeconds(20));

                Assert.AreEqual(1, hits, "one request for " + callers + " callers");
                foreach (var key in keys)
                {
                    Assert.AreEqual(Pem, key);
                }
            }
            finally
            {
                release.TrySetResult(true);
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A key the creator has confirmed for two minutes is served for
        /// every minute between them without a request, because a key is in
        /// force from the start of its period until the next key starts. A
        /// minute outside the confirmed span is asked about, and the answer
        /// widens the span.
        /// </summary>
        [TestMethod]
        public async Task AMinuteBetweenTwoConfirmedMinutesIsServedFromTheCache()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () =>
            {
                Interlocked.Increment(ref hits);
                return Task.FromResult(200);
            });

            try
            {
                // The week before the fixture minute, so every minute here
                // is in the past and the cache reads each as itself.
                var first = Minute - Week;
                var last = Minute - 1;
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, last));
                Assert.AreEqual(2, hits, "the two ends of the span were asked about");

                foreach (var between in new[] { first + 1, first + Week / 2, last - 1 })
                {
                    var key = await CryptoExtensions.GetPublicKeyAsync(
                        Dated(prefix, between));
                    Assert.AreEqual(Pem, key);
                }
                Assert.AreEqual(2, hits,
                    "a minute between two confirmed minutes is not asked about");
                Assert.AreEqual(1, CryptoExtensions.CachedKeyCount,
                    "one key is held however many minutes it covers");

                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, last + 1));
                Assert.AreEqual(3, hits, "a minute past the span is asked about");
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first - 1));
                Assert.AreEqual(4, hits, "a minute before the span is asked about");
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, last + 1));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first - 1));
                Assert.AreEqual(4, hits, "the span now takes in both");
                Assert.AreEqual(1, CryptoExtensions.CachedKeyCount,
                    "the same key was answered, so the span widened rather "
                    + "than a second key being held");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// The case that made the cache almost useless when it was keyed by
        /// the whole URL. A hundred identifiers with a hundred different
        /// minutes inside one key's period cost a hundred requests then.
        /// With the ends of the period confirmed they cost none.
        /// </summary>
        [TestMethod]
        public async Task AHundredIdentifiersInOneConfirmedPeriodMakeNoRequest()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () =>
            {
                Interlocked.Increment(ref hits);
                return Task.FromResult(200);
            });

            try
            {
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, Minute));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, Minute + 100));
                for (uint i = 1; i <= 100; i++)
                {
                    await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, Minute + i));
                }
                Assert.AreEqual(2, hits,
                    "a hundred identifiers over a hundred minutes made no "
                    + "request once both ends of the span were known");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A key is only ever served for a minute inside the span the
        /// creator has confirmed it for. Where the creator rotated between
        /// two confirmed minutes, the minutes between them belong to
        /// neither key until the creator is asked, and every answer agrees
        /// with what the creator would have said.
        /// </summary>
        [TestMethod]
        public async Task AKeyIsNeverServedForAMinuteOutsideItsConfirmedSpan()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var earlier = FreshPem();
            var later = FreshPem();
            // A week before the fixture minute, so the fortnight around it
            // is in the past and the cache reads each minute as itself.
            var rotation = Minute - Week;
            Func<uint, string> inForce = minute => minute < rotation ? earlier : later;
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(
                creator,
                stop.Token,
                () =>
                {
                    Interlocked.Increment(ref hits);
                    return Task.FromResult(200);
                },
                request => inForce(DateOf(request)!.Value));

            try
            {
                // A minute a week before the rotation and one a week after
                // it, so the two keys are held with the rotation between.
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, rotation - Week));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, rotation + Week));
                Assert.AreEqual(2, hits);
                Assert.AreEqual(2, CryptoExtensions.CachedKeyCount);

                // Every minute across the rotation, in an order that walks
                // in from both sides, is answered with the key the creator
                // would give, whether from the cache or by asking.
                var minutes = new[]
                {
                    rotation - 1, rotation, rotation - 2, rotation + 1,
                    rotation - Week / 2, rotation + Week / 2,
                    rotation - 3, rotation + 2, rotation - 1, rotation,
                };
                foreach (var minute in minutes)
                {
                    var key = await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, minute));
                    Assert.AreEqual(inForce(minute), key,
                        "the key served for minute " + minute);
                }
                Assert.AreEqual(2, CryptoExtensions.CachedKeyCount,
                    "two keys are held, each with its own span");
                Assert.IsTrue(hits > 2 && hits < 2 + minutes.Length,
                    "some minutes were asked about and some were served: " + hits);

                // The minute either side of the rotation is now confirmed,
                // so nothing across the whole fortnight needs asking.
                var before = hits;
                for (var minute = rotation - Week; minute <= rotation + Week; minute += 60)
                {
                    var key = await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, minute));
                    Assert.AreEqual(inForce(minute), key,
                        "the key served for minute " + minute);
                }
                Assert.AreEqual(before, hits,
                    "both spans are fully confirmed, so nothing was asked");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A minute within the clock drift allowance of now, or later, is
        /// asked about every time and never held, because a creator whose
        /// clock differs from this one's may have read it as its present
        /// rather than as the minute named. A minute beyond the allowance is
        /// held as usual. Live identifiers therefore cost one request per minute per creator and older ones cost none.
        /// </summary>
        [TestMethod]
        public async Task AMinuteWithinTheDriftAllowanceIsNotHeld()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () =>
            {
                Interlocked.Increment(ref hits);
                return Task.FromResult(200);
            });

            try
            {
                var started = Now();
                var recent = started - 1;
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, recent));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, recent));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, started + Week));
                await CryptoExtensions.GetPublicKeyAsync(
                    new Uri(prefix + "owid/api/v3/public-key?format=pkcs"));
                var old = started - Allowance() - 1;
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, old));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, old));
                if (Now() != started)
                {
                    Assert.Inconclusive(
                        "the minute changed during the test, so the calls "
                        + "were not all about the same now");
                }
                Assert.AreEqual(5, hits,
                    "the recent minute was asked about twice, the future "
                    + "minute and the request with no date once each, and "
                    + "the old minute once with the second call held");
                Assert.AreEqual(1, CryptoExtensions.CachedKeyCount,
                    "only the old minute's key is held");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// Serves every request with the answer the second handler gives for
        /// the date the request names, as JSON, the way the controller in
        /// this library answers. Counts the requests.
        /// </summary>
        private static Task ServeJson(
            HttpListener listener,
            CancellationToken stop,
            Func<uint?, Model.PublicKeyResponse> answerFor,
            Action counted)
        {
            return Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await listener.GetContextAsync(); }
                    catch (Exception) { return; }
                    try
                    {
                        counted();
                        var answer = answerFor(DateOf(context.Request));
                        var bytes = Encoding.UTF8.GetBytes(
                            System.Text.Json.JsonSerializer.Serialize(answer));
                        context.Response.StatusCode = 200;
                        context.Response.ContentType = "application/json; charset=utf-8";
                        await context.Response.OutputStream.WriteAsync(
                            bytes, 0, bytes.Length);
                        context.Response.Close();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                }
            });
        }

        /// <summary>
        /// The base date the OWID date counts minutes from.
        /// </summary>
        private static readonly DateTime BaseDate =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// A JSON answer for a key covering the minutes from first up to but
        /// not including end.
        /// </summary>
        private static Model.PublicKeyResponse Answer(string pem, uint first, uint? end)
        {
            return new Model.PublicKeyResponse
            {
                PublicKey = pem,
                ValidFrom = BaseDate.AddMinutes(first),
                ValidTo = end == null ? null : BaseDate.AddMinutes(end.Value),
            };
        }

        /// <summary>
        /// A creator that answers the JSON form, stating the moments the key
        /// is valid from and to, has the whole span held from that one
        /// answer, so every other minute of the span is served without a
        /// request.
        /// </summary>
        [TestMethod]
        public async Task AKeyAnsweredWithItsSpanIsHeldForTheWholeSpan()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            // Weeks counted from the fixture minute, each with its own key.
            var serving = ServeJson(creator, stop.Token, date =>
            {
                var week = (date!.Value - (Minute - 10 * Week)) / Week;
                var first = Minute - 10 * Week + week * Week;
                return Answer(DistinctPem(week), first, first + Week);
            }, () => Interlocked.Increment(ref hits));

            try
            {
                var first = Minute - Week;
                var pem = await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first + 1));
                foreach (var minute in new[] { first, first + Week / 2, first + Week - 1 })
                {
                    Assert.AreEqual(pem, await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, minute)),
                        "the key served for minute " + minute);
                }
                Assert.AreEqual(1, hits, "the whole week was held from one answer");
                Assert.AreEqual(1, CryptoExtensions.CachedKeyCount);

                var before = await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first - 1));
                Assert.AreNotEqual(pem, before, "the minute before the week is the earlier week's key");
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, first - Week));
                Assert.AreEqual(2, hits, "the earlier week was held from its one answer");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// The drift allowance, which keeps minutes near now out of a cache
        /// built from confirmed minutes, does not apply to a span the
        /// creator stated itself, so live identifiers cost one request per
        /// key rather than one per minute.
        /// </summary>
        [TestMethod]
        public async Task ARecentMinuteIsServedWhereTheCreatorStatedTheSpan()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            var now = Now();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            // One key covering the day either side of now.
            var serving = ServeJson(creator, stop.Token,
                date => Answer(Pem, now - 24 * 60, now + 24 * 60),
                () => Interlocked.Increment(ref hits));

            try
            {
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, now - 1));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, now));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, now - 10));
                await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, now + 60));
                Assert.AreEqual(1, hits,
                    "the current key was served for every recent minute from one answer");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// An identifier dated just after a key started, but signed with the
        /// key before it, verifies, and one dated just before a key started
        /// but signed with it verifies too, because the neighbouring key is
        /// tried when the selected key fails within the drift allowance of
        /// the span's edge. Further from the edge the failure stands.
        /// </summary>
        [TestMethod]
        public async Task ASignatureFailingNearTheEdgeOfASpanIsCheckedAgainstTheNeighbour()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var firstKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var secondKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var firstPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", firstKey.ExportSubjectPublicKeyInfo()));
            var secondPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", secondKey.ExportSubjectPublicKeyInfo()));
            var start = Minute - 2 * Week;
            var rotation = Minute - Week;
            var end = Minute;
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = ServeJson(creator, stop.Token,
                date => date!.Value < rotation
                    ? Answer(firstPem, start, rotation)
                    : Answer(secondPem, rotation, end),
                () => Interlocked.Increment(ref hits));

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                var signedFirst = new Creator("creator.test", firstKey);
                var signedSecond = new Creator("creator.test", secondKey);
                var payload = Encoding.UTF8.GetBytes("payload");

                // Dated five minutes into the second key's span, signed with
                // the first.
                var late = signedFirst.Create(payload, BaseDate.AddMinutes(rotation + 5));
                Assert.IsTrue(
                    await late.VerifyAtAsync(endPoint, default),
                    "an identifier signed with the earlier key just after the rotation verifies");
                Assert.AreEqual(2, hits, "the selected key and then the earlier key were asked for");

                // Dated five minutes before the rotation, signed with the
                // second key.
                var early = signedSecond.Create(payload, BaseDate.AddMinutes(rotation - 5));
                Assert.IsTrue(
                    await early.VerifyAtAsync(endPoint, default),
                    "an identifier signed with the later key just before the rotation verifies");
                Assert.AreEqual(2, hits, "both keys are held with their spans, so nothing more was asked");

                // Dated twenty minutes into the second key's span, signed
                // with the first, which is further from the edge than clocks
                // are allowed to differ.
                var far = signedFirst.Create(payload, BaseDate.AddMinutes(rotation + 20));
                Assert.IsFalse(
                    await far.VerifyAtAsync(endPoint, default),
                    "an identifier well inside the later key's span signed with the earlier key does not verify");
                Assert.AreEqual(2, hits, "the identifier is further from every edge than clocks may differ");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// The neighbouring key is asked for by the minute just beyond the
        /// edge of the span the creator stated, not by a minute a fixed
        /// distance from the identifier, so a key in force for less than the
        /// drift allowance is still the one tried.
        /// </summary>
        [TestMethod]
        public async Task TheNeighbourIsAskedForByTheMinuteJustBeyondTheEdge()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var firstKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var secondKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var firstPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", firstKey.ExportSubjectPublicKeyInfo()));
            var secondPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", secondKey.ExportSubjectPublicKeyInfo()));
            var start = Minute - 2 * Week;
            var rotation = Minute - Week;
            var end = Minute;
            var asked = new System.Collections.Concurrent.ConcurrentQueue<uint?>();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = ServeJson(creator, stop.Token,
                date =>
                {
                    asked.Enqueue(date);
                    return date!.Value < rotation
                        ? Answer(firstPem, start, rotation)
                        : Answer(secondPem, rotation, end);
                },
                () => { });

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                var payload = Encoding.UTF8.GetBytes("payload");
                var late = new Creator("creator.test", firstKey)
                    .Create(payload, BaseDate.AddMinutes(rotation + 5));
                Assert.IsTrue(
                    await late.VerifyAtAsync(endPoint, default));
                CollectionAssert.AreEqual(
                    new uint?[] { rotation + 5, rotation - 1 },
                    asked.ToArray(),
                    "the identifier's own minute and then the minute just before the span started");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A key the creator states a start for and no end is in force until
        /// further notice as far as the creator has said, so a live
        /// identifier dated just after that start which does not verify
        /// under it is checked against the key before it, even though the
        /// cache holds the key only up to the drift allowance behind now.
        /// </summary>
        [TestMethod]
        public async Task AKeyStatedWithoutAnEndHasNoLaterEdge()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var firstKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var secondKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var firstPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", firstKey.ExportSubjectPublicKeyInfo()));
            var secondPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", secondKey.ExportSubjectPublicKeyInfo()));
            var rotation = Now() - 5;
            var start = rotation - Week;
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = ServeJson(creator, stop.Token,
                date => date!.Value < rotation
                    ? Answer(firstPem, start, rotation)
                    : Answer(secondPem, rotation, null),
                () => Interlocked.Increment(ref hits));

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                var payload = Encoding.UTF8.GetBytes("payload");
                var live = new Creator("creator.test", firstKey)
                    .Create(payload, BaseDate.AddMinutes(rotation + 2));
                Assert.IsTrue(
                    await live.VerifyAtAsync(endPoint, default),
                    "a live identifier signed with the key before the current one verifies");
                Assert.AreEqual(2, hits, "the current key and then the key before it were asked for");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A creator whose own statement puts the identifier's date outside
        /// the span of the key it answered with has said that key did not
        /// sign at that date, so nothing verifying under it leaves the key
        /// unavailable rather than the signature not matching. A forgery
        /// dated inside the span is still reported as not matching.
        /// </summary>
        [TestMethod]
        public async Task AKeyTheCreatorSaysWasNotInForceLeavesTheSignatureUnjudged()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var firstKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var secondKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var strangerKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var secondPem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", secondKey.ExportSubjectPublicKeyInfo()));
            var rotation = Minute - Week;
            var end = Minute;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            // A creator that ignores the date asked about and answers with
            // the current key and its span whatever the request.
            var serving = ServeJson(creator, stop.Token,
                date => Answer(secondPem, rotation, end),
                () => { });

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                var payload = Encoding.UTF8.GetBytes("payload");
                var earlier = new Creator("creator.test", firstKey)
                    .Create(payload, BaseDate.AddMinutes(rotation - 3 * 24 * 60));
                Assert.AreEqual(
                    Model.OwidSignatureStatus.KeyUnavailable,
                    await earlier.SignatureStatusAtAsync(endPoint, default),
                    "the key answered with was not in force at the identifier's date");
                await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                    () => earlier.VerifyAtAsync(endPoint, default),
                    "the boolean form cannot say false without it reading as a forgery");

                var forged = new Creator("creator.test", strangerKey)
                    .Create(payload, BaseDate.AddMinutes(rotation + 3 * 24 * 60));
                Assert.AreEqual(
                    Model.OwidSignatureStatus.SignatureInvalid,
                    await forged.SignatureStatusAtAsync(endPoint, default),
                    "a signature failing under the key in force at its date does not match");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// Closes the loop between the two halves of this library. The
        /// controller answers from a schedule, exactly as it would over
        /// HTTP, the stand in creator replays that answer byte for byte, and
        /// the client verifies identifiers against it, holding the whole
        /// span from the one answer.
        /// </summary>
        [TestMethod]
        public async Task TheControllerAnswersWhatTheClientReads()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var previousKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var currentKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var nextKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            string PemOf(System.Security.Cryptography.ECDsa key) => new string(
                System.Security.Cryptography.PemEncoding.Write(
                    "PUBLIC KEY", key.ExportSubjectPublicKeyInfo()));
            var rotation = BaseDate.AddMinutes(Minute - Week);
            var store = new Model.DatedKeyStore(new[]
            {
                new Model.DatedPublicKey { StartsAt = rotation.AddDays(-7), PublicKey = PemOf(previousKey) },
                new Model.DatedPublicKey { StartsAt = rotation, PublicKey = PemOf(currentKey) },
                new Model.DatedPublicKey { StartsAt = rotation.AddDays(7), PublicKey = PemOf(nextKey) },
            });
            var configuration = new Model.Configuration.OwidConfiguration
            {
                Domain = "creator.test",
                PublicKey = PemOf(currentKey),
                PrivateKey = new string(System.Security.Cryptography.PemEncoding.Write(
                    "PRIVATE KEY", currentKey.ExportPkcs8PrivateKey())),
            };
            using var controller = new Controllers.OwidController(configuration, store);
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = ServeJson(creator, stop.Token, date =>
            {
                // What the controller itself answers for the request.
                var result = controller.GetPublicKey(date).GetAwaiter().GetResult();
                Assert.IsNotNull(result.Value, "the controller answered the request");
                return result.Value!;
            }, () => Interlocked.Increment(ref hits));

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                var payload = Encoding.UTF8.GetBytes("payload");
                var signedCurrent = new Creator("creator.test", currentKey);
                var first = signedCurrent.Create(payload, rotation.AddDays(3));
                Assert.IsTrue(await first.VerifyAtAsync(endPoint, default),
                    "the identifier verifies against the key the controller answered with");
                var second = signedCurrent.Create(payload, rotation.AddDays(6));
                Assert.IsTrue(await second.VerifyAtAsync(endPoint, default),
                    "a second identifier in the same week verifies");
                Assert.AreEqual(1, hits, "the whole week was held from the controller's one answer");

                var late = new Creator("creator.test", previousKey).Create(payload, rotation.AddMinutes(5));
                Assert.IsTrue(await late.VerifyAtAsync(endPoint, default),
                    "an identifier signed with the earlier key just after the rotation verifies");
                Assert.AreEqual(2, hits, "the earlier key was asked for once");

                var forged = new Creator("creator.test", nextKey).Create(payload, rotation.AddDays(3));
                Assert.IsFalse(await forged.VerifyAtAsync(endPoint, default),
                    "an identifier signed with a key not in force at its date does not verify");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// The PEM alone as text is refused rather than used, and so is a span that ends before it starts.
        /// </summary>
        [TestMethod]
        public async Task AnAnswerThatIsNotTheJsonFormIsRefused()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var textOnly = true;
            var serving = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await creator.GetContextAsync(); }
                    catch (Exception) { return; }
                    try
                    {
                        var body = textOnly
                            ? Pem
                            : System.Text.Json.JsonSerializer.Serialize(new Model.PublicKeyResponse
                            {
                                PublicKey = Pem,
                                ValidFrom = BaseDate.AddMinutes(Minute),
                                ValidTo = BaseDate.AddMinutes(Minute - Week),
                            });
                        var bytes = Encoding.UTF8.GetBytes(body);
                        context.Response.ContentType = textOnly ? "text/plain" : "application/json";
                        await context.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                        context.Response.Close();
                    }
                    catch (Exception) { return; }
                }
            });

            try
            {
                await Assert.ThrowsExactlyAsync<ArgumentException>(
                    () => CryptoExtensions.GetPublicKeyAsync(Dated(prefix, Minute)),
                    "the PEM alone is not the JSON form the specification requires");
                textOnly = false;
                await Assert.ThrowsExactlyAsync<ArgumentException>(
                    () => CryptoExtensions.GetPublicKeyAsync(Dated(prefix, Minute)),
                    "a span that ends before it starts is refused");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// Threads verifying the same OWID at the same moment make one request
        /// for its key between them, and every one of them gets the answer.
        /// The stand in creator holds its answer until every thread has
        /// asked, so all of them are in flight together against one request.
        /// </summary>
        [TestMethod]
        public async Task ManyThreadsVerifyingOneOwidTogetherMakeOneRequest()
        {
            const int callers = 32;
            CryptoExtensions.ClearPublicKeyCache();
            using var key = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var pem = new string(System.Security.Cryptography.PemEncoding.Write(
                "PUBLIC KEY", key.ExportSubjectPublicKeyInfo()));
            var owid = new Creator("creator.test", key).Create(
                Encoding.UTF8.GetBytes("payload"), BaseDate.AddMinutes(Minute));
            var hits = 0;
            var release = new TaskCompletionSource<bool>();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await creator.GetContextAsync(); }
                    catch (Exception) { return; }
                    try
                    {
                        Interlocked.Increment(ref hits);
                        await release.Task;
                        var bytes = Encoding.UTF8.GetBytes(
                            System.Text.Json.JsonSerializer.Serialize(
                                new Model.PublicKeyResponse { PublicKey = pem }));
                        context.Response.ContentType = "application/json";
                        await context.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                        context.Response.Close();
                    }
                    catch (Exception) { return; }
                }
            });

            try
            {
                var endPoint = prefix + "owid/api/v3/public-key";
                using var start = new Barrier(callers + 1);
                var verifying = new Task<bool>[callers];
                for (var i = 0; i < callers; i++)
                {
                    verifying[i] = Task.Factory.StartNew(() =>
                    {
                        start.SignalAndWait();
                        return owid.VerifyAtAsync(endPoint, default)
                            .GetAwaiter().GetResult();
                    }, TaskCreationOptions.LongRunning);
                }
                // Every thread goes at the same moment, and the creator only
                // answers once they are all waiting on it.
                start.SignalAndWait();
                await Task.Delay(200);
                release.SetResult(true);
                var results = await Task.WhenAll(verifying).WaitAsync(TimeSpan.FromSeconds(30));
                Assert.IsTrue(results.All(valid => valid), "every thread verified the OWID");
                Assert.AreEqual(1, hits, "one request for " + callers + " threads");
            }
            finally
            {
                release.TrySetResult(true);
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// The cache does not grow without limit. A key url carries the
        /// domain and the date of the OWID being verified, so the number of
        /// distinct keys a verifier is shown is chosen by whoever presents
        /// the OWIDs rather than by this process, and an unbounded cache
        /// would grow on their input. The stand in creator here answers
        /// every minute with a different key, which is the worst a creator
        /// can do to the cache.
        /// </summary>
        [TestMethod]
        public async Task TheCacheDoesNotGrowWithoutLimit()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(
                creator,
                stop.Token,
                () => Task.FromResult(200),
                request => DistinctPem(DateOf(request)!.Value));

            try
            {
                // One more distinct key than the cache is allowed to hold,
                // each standing for an OWID with its own date.
                var maximum = Maximum();
                for (var i = 0; i <= maximum; i++)
                {
                    await CryptoExtensions.GetPublicKeyAsync(Dated(prefix, (uint)i));
                }

                Assert.IsTrue(
                    Held() <= maximum,
                    "held " + Held() + " of at most " + maximum);
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// Emptying the cache means the next caller fetches again.
        /// </summary>
        [TestMethod]
        public async Task ClearingTheCacheCausesAFreshFetch()
        {
            CryptoExtensions.ClearPublicKeyCache();
            var hits = 0;
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () =>
            {
                Interlocked.Increment(ref hits);
                return Task.FromResult(200);
            });

            try
            {
                var url = Dated(prefix, Minute);
                await CryptoExtensions.GetPublicKeyAsync(url);
                await CryptoExtensions.GetPublicKeyAsync(url);
                Assert.AreEqual(1, hits, "the second call came from the cache");

                CryptoExtensions.ClearPublicKeyCache();
                await CryptoExtensions.GetPublicKeyAsync(url);
                Assert.AreEqual(2, hits, "the cache was emptied so this fetched");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                await serving.WaitAsync(TimeSpan.FromSeconds(5));
                CryptoExtensions.ClearPublicKeyCache();
            }
        }

        /// <summary>
        /// A public key that differs for every value, so the bound is tested
        /// against distinct keys that all pass the check a creator applies
        /// before answering. Each is a real key pair, made once and kept.
        /// </summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<uint, string> DistinctKeys =
            new System.Collections.Concurrent.ConcurrentDictionary<uint, string>();

        private static string DistinctPem(uint value)
        {
            return DistinctKeys.GetOrAdd(value, _ => FreshPem());
        }

        /// <summary>
        /// The bound the library holds itself to, read from the library so
        /// the test cannot drift from it.
        /// </summary>
        private static int Maximum()
        {
            var field = typeof(CryptoExtensions).GetField(
                "MaximumCachedKeys",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.IsNotNull(field, "the cache states its own limit");
            return (int)field!.GetRawConstantValue()!;
        }

        /// <summary>
        /// The clock drift allowance the library holds itself to, read from
        /// the library so the test cannot drift from it.
        /// </summary>
        private static uint Allowance()
        {
            var field = typeof(CryptoExtensions).GetField(
                "ClockDriftAllowanceMinutes",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.IsNotNull(field, "the cache states its drift allowance");
            return (uint)field!.GetRawConstantValue()!;
        }

        /// <summary>
        /// How many keys the cache is holding.
        /// </summary>
        private static int Held()
        {
            return CryptoExtensions.CachedKeyCount;
        }

        /// <summary>
        /// Nothing on the verification surface reaches the network without
        /// returning a task. There was once a synchronous fetch with a
        /// blocking wait inside it, and a caller on a request thread could
        /// pin that thread for the length of a network round trip.
        /// </summary>
        [TestMethod]
        public void EveryKeyFetchReturnsATask()
        {
            var fetches = typeof(CryptoExtensions)
                .GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic |
                    BindingFlags.Static | BindingFlags.Instance)
                .Where(m => m.Name.Contains("PublicKey"))
                // Emptying the cache is not a fetch, so it is not
                // required to hand back a task.
                .Where(m => m.Name != nameof(
                    CryptoExtensions.ClearPublicKeyCache))
                .ToArray();

            Assert.IsTrue(fetches.Length > 0, "the fetch still exists");
            var synchronous = fetches
                .Where(m => typeof(Task).IsAssignableFrom(m.ReturnType) == false)
                .Select(m => m.Name)
                .ToArray();
            Assert.AreEqual(
                0,
                synchronous.Length,
                "synchronous fetch: " + string.Join(", ", synchronous));
            Assert.IsFalse(
                fetches.Any(m => m.Name == "GetPublicKey"),
                "the synchronous GetPublicKey has been removed");
        }
    }
}
