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
        private const string Pem =
            "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n";

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
        /// send, and a 200 carries as its body the PEM the second handler
        /// gives for the request, or the fixed PEM where there is none.
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
                            var bytes = Encoding.UTF8.GetBytes(pem);
                            context.Response.ContentType = "text/plain";
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
            const string earlier = "-----BEGIN PUBLIC KEY-----\nZWFybGllcg==\n-----END PUBLIC KEY-----\n";
            const string later = "-----BEGIN PUBLIC KEY-----\nbGF0ZXI=\n-----END PUBLIC KEY-----\n";
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
        /// held as usual. Live identifiers therefore cost one request per
        /// minute per creator, as they always did, and older ones cost none.
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
                request => "-----BEGIN PUBLIC KEY-----\n"
                    + DateOf(request)
                    + "\n-----END PUBLIC KEY-----\n");

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
