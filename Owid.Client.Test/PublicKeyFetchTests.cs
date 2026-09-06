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
    /// shares one request between callers that arrive together, and never
    /// keeps a failed request in the cache.
    /// </summary>
    [TestClass]
    public class PublicKeyFetchTests
    {
        private const string Pem =
            "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n";

        /// <summary>
        /// Serves every request the listener receives with the handler's
        /// verdict, until stopped. The handler returns the status code to
        /// send, and a 200 carries the PEM as its body.
        /// </summary>
        private static Task Serve(
            HttpListener listener,
            CancellationToken stop,
            Func<Task<int>> handler)
        {
            return Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await listener.GetContextAsync(); }
                    catch (Exception) { return; }
                    var status = await handler();
                    context.Response.StatusCode = status;
                    if (status == 200)
                    {
                        var bytes = Encoding.UTF8.GetBytes(Pem);
                        context.Response.ContentType = "text/plain";
                        await context.Response.OutputStream.WriteAsync(
                            bytes, 0, bytes.Length);
                    }
                    context.Response.Close();
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
                var url = new Uri(prefix + "owid/api/v3/public-key?format=pkcs");
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
            }
        }

        /// <summary>
        /// A request that fails is not kept, so the next caller tries again
        /// rather than being handed the earlier failure.
        /// </summary>
        [TestMethod]
        public async Task AFailedRequestIsNotCached()
        {
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
                var url = new Uri(prefix + "owid/api/v3/public-key?format=pkcs");
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
            }
        }

        /// <summary>
        /// A caller whose token is cancelled stops waiting, and the wait
        /// ends with the cancellation rather than with a key.
        /// </summary>
        [TestMethod]
        public async Task ACancelledCallerStopsWaiting()
        {
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
                var url = new Uri(prefix + "owid/api/v3/public-key?format=pkcs");
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
            }
        }

        /// <summary>
        /// The cache does not grow without limit. A key url carries the
        /// domain and the date of the OWID being verified, so the number of
        /// distinct urls is chosen by whoever presents the OWIDs rather than
        /// by this process, and an unbounded cache would grow on their input.
        /// </summary>
        [TestMethod]
        public async Task TheCacheDoesNotGrowWithoutLimit()
        {
            CryptoExtensions.ClearPublicKeyCache();
            using var creator = Loopback.Listen(out var prefix);
            using var stop = new CancellationTokenSource();
            var serving = Serve(creator, stop.Token, () => Task.FromResult(200));

            try
            {
                // One more distinct url than the cache is allowed to hold,
                // each standing for an OWID with its own date.
                var maximum = Maximum();
                for (var i = 0; i <= maximum; i++)
                {
                    await CryptoExtensions.GetPublicKeyAsync(new Uri(
                        prefix + "owid/api/v3/public-key?format=pkcs&date=" + i));
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
                var url = new Uri(prefix + "owid/api/v3/public-key?format=pkcs");
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
        /// How many keys the cache is holding.
        /// </summary>
        private static int Held()
        {
            var field = typeof(CryptoExtensions).GetField(
                "_publicKeyCache",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.IsNotNull(field, "the cache exists");
            dynamic cache = field!.GetValue(null)!;
            return (int)cache.Count;
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
