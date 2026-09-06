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
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Owid.Client.Test
{
    /// <summary>
    /// A creator whose domain answers with a redirect does not get the key
    /// at the other end trusted as its own. The other end here would serve
    /// a key, so following the redirect would yield one, and refusing it
    /// must surface as a failure to obtain the key with the request to the
    /// other host never made. Without this a network attacker able to bend
    /// a creator's DNS, or a misconfigured creator, could substitute the
    /// key and forgeries would verify.
    /// </summary>
    [TestClass]
    public class RedirectTests
    {
        private static HttpListener Listen(out string prefix)
        {
            // A free port, found by binding and releasing it.
            var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            prefix = $"http://127.0.0.1:{port}/";
            var listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            listener.Start();
            return listener;
        }

        [TestMethod]
        public void ARedirectIsNotFollowed()
        {
            var elsewhereHits = 0;
            using var elsewhere = Listen(out var elsewherePrefix);
            using var creator = Listen(out var creatorPrefix);
            using var stop = new CancellationTokenSource();

            var serveElsewhere = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await elsewhere.GetContextAsync(); }
                    catch (Exception) { return; }
                    Interlocked.Increment(ref elsewhereHits);
                    var bytes = Encoding.UTF8.GetBytes(
                        "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n");
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "text/plain";
                    await context.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                    context.Response.Close();
                }
            });
            var serveCreator = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try { context = await creator.GetContextAsync(); }
                    catch (Exception) { return; }
                    context.Response.StatusCode = 302;
                    context.Response.RedirectLocation = elsewherePrefix + "key.pem";
                    context.Response.Close();
                }
            });

            try
            {
                var url = new Uri(creatorPrefix + "owid/api/v3/public-key?format=pkcs");
                HttpRequestException? refused = null;
                try
                {
                    CryptoExtensions.GetPublicKey(url);
                    Assert.Fail("a redirect must not yield a key");
                }
                catch (AggregateException thrown)
                {
                    refused = thrown.InnerException as HttpRequestException;
                }
                catch (HttpRequestException thrown)
                {
                    refused = thrown;
                }
                Assert.IsNotNull(refused,
                    "the refusal surfaces as the failure to obtain the key");
                Assert.AreEqual(HttpStatusCode.Found, refused!.StatusCode,
                    "the 302 is carried");
                Assert.AreEqual(0, elsewhereHits,
                    "the request that would have gone to the other host was never made");
            }
            finally
            {
                stop.Cancel();
                creator.Stop();
                elsewhere.Stop();
                Task.WaitAll(new[] { serveCreator, serveElsewhere }, TimeSpan.FromSeconds(5));
            }
        }
    }
}
