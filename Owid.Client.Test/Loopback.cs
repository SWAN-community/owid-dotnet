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

using System.Net;

namespace Owid.Client.Test
{
    /// <summary>
    /// A stand in for a creator's key endpoint on the loopback address, used
    /// by the tests that exercise the key fetch without reaching the network.
    /// </summary>
    internal static class Loopback
    {
        /// <summary>
        /// Starts listening on a free port and returns the listener, with
        /// the prefix it is bound to.
        /// </summary>
        public static HttpListener Listen(out string prefix)
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
    }
}
