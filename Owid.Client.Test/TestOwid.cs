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
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// Parses input a test has already decided is valid.
    /// </summary>
    /// <remarks>
    /// Most tests are about something other than parsing and simply need an
    /// OWID to work with. They used to write <c>new Owid(value)</c>, which no
    /// longer exists, because an OWID now arrives only from a successful parse
    /// or from a creator. This keeps those tests reading as they did while
    /// going through the public surface, and fails loudly with the reason if
    /// input a test assumed was good turns out not to be.
    ///
    /// Tests that are about parsing call <c>TryParse</c> directly and assert
    /// the status themselves. This helper is deliberately not used there.
    /// </remarks>
    internal static class TestOwid
    {
        /// <summary>
        /// The OWID encoded in the value, failing the test if it is not one.
        /// </summary>
        internal static Model.Owid Parse(string value)
        {
            Assert.IsTrue(
                Model.Owid.TryParse(value, out var owid, out var status),
                $"the test expected valid input, and parsing gave {status}");
            Assert.IsNotNull(owid);
            return owid!;
        }

        /// <summary>
        /// The OWID in the buffer, failing the test if it is not one.
        /// </summary>
        internal static Model.Owid Parse(byte[] buffer)
        {
            Assert.IsTrue(
                Model.Owid.TryParse(buffer, out var owid, out var status),
                $"the test expected valid input, and parsing gave {status}");
            Assert.IsNotNull(owid);
            return owid!;
        }

        /// <summary>
        /// Asserts everything the parse contract promises on failure: it does
        /// not throw, it reports failure, it hands back no value, and it names
        /// the reason.
        /// </summary>
        internal static void AssertRefused(
            byte[] buffer,
            OwidParseStatus expected,
            string context = "")
        {
            var parsed = Model.Owid.TryParse(
                buffer, out var owid, out var status);
            Assert.IsFalse(parsed, $"should be refused. {context}");
            Assert.IsNull(owid, $"no value on failure. {context}");
            Assert.AreEqual(expected, status, context);
        }
    }
}
