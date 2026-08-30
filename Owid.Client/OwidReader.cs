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
using System.Text;
using Owid.Client.Model;

namespace Owid.Client
{
    /// <summary>
    /// Reads a complete OWID from a buffer, reporting why rather than
    /// throwing when the bytes are not one.
    /// </summary>
    /// <remarks>
    /// This walks the buffer by index and checks every read against what is
    /// left, so a malformed envelope is a comparison that fails rather than an
    /// exception that unwinds. That matters because the data comes from
    /// outside: an attacker chooses how often this fails and how large the
    /// input is, and an exception per attempt is a cost they control.
    ///
    /// It deliberately does not call the throwing parser and catch. The
    /// exception would still be constructed and unwound, so the cost would
    /// remain and only the surface would look different.
    ///
    /// This is the exact-buffer contract: the envelope must end where the
    /// buffer does. Framed reading, where an envelope is followed by more
    /// data, stays with the stream reader in Extensions, which must not
    /// require the end of the stream because what follows may be the next
    /// envelope rather than rubbish.
    /// </remarks>
    internal static class OwidReader
    {
        /// <summary>
        /// Reads one complete OWID occupying the whole of
        /// <paramref name="buffer"/>.
        /// </summary>
        /// <returns>
        /// <see cref="OwidParseStatus.Parsed"/> with
        /// <paramref name="owid"/> set, or the reason it is not an OWID with
        /// <paramref name="owid"/> null. Both outputs are always assigned.
        /// </returns>
        internal static OwidParseStatus TryRead(
            byte[] buffer,
            out Model.Owid? owid)
        {
            owid = null;
            if (buffer == null)
            {
                return OwidParseStatus.MissingInput;
            }

            var at = 0;
            if (Remaining(buffer, at) < 1)
            {
                return OwidParseStatus.UnexpectedEnd;
            }

            var version = (OwidVersion)buffer[at++];
            switch (version)
            {
                case OwidVersion.Empty:
                    // An empty OWID is the version byte and nothing else, so
                    // anything after it belongs to no field.
                    if (at != buffer.Length)
                    {
                        return OwidParseStatus.MalformedEnvelope;
                    }
                    owid = Model.Owid.CreateForParser(
                        version,
                        string.Empty,
                        Constants.BaseDate,
                        Array.Empty<byte>(),
                        Array.Empty<byte>());
                    return OwidParseStatus.Parsed;

                case OwidVersion.Version1:
                case OwidVersion.Version2:
                case OwidVersion.Version3:
                    break;

                default:
                    return OwidParseStatus.UnsupportedVersion;
            }

            var domainStatus = ReadDomain(buffer, ref at, out var domain);
            if (domainStatus != OwidParseStatus.Parsed)
            {
                return domainStatus;
            }

            var dateStatus = ReadDate(buffer, ref at, version, out var date);
            if (dateStatus != OwidParseStatus.Parsed)
            {
                return dateStatus;
            }

            if (Remaining(buffer, at) < sizeof(uint))
            {
                return OwidParseStatus.UnexpectedEnd;
            }
            var declared = (uint)(
                buffer[at] |
                (buffer[at + 1] << 8) |
                (buffer[at + 2] << 16) |
                (buffer[at + 3] << 24));
            at += sizeof(uint);

            // The declaration is the sender's claim about a payload we have
            // not read yet, so it is compared with what is actually here
            // before anything is sized by it. Computed signed and wide, so
            // that a buffer with
            // fewer bytes left than a signature needs produces a negative
            // count rather than wrapping to a large positive one. A negative
            // count can never equal a declaration, so such an envelope is
            // reported as the disagreement it is.
            //
            // The disagreement is the finding even when the buffer also
            // stopped early: what a reader can say for certain is that the
            // declared payload cannot leave exactly the signature the version
            // requires, and that is true whichever way the bytes fall short.
            // Reporting it as a truncation instead would name a different
            // fault for the same evidence.
            var remaining = Remaining(buffer, at);
            var present = remaining - Constants.SignatureLength;
            if (present != (long)declared)
            {
                return OwidParseStatus.ByteCountMismatch;
            }

            // The bytes are all here. Whether this runtime can hold them in
            // one array is a separate question, and a different answer,
            // because the same envelope may be readable elsewhere.
            if (declared > Array.MaxLength)
            {
                return OwidParseStatus.ImplementationCapacityExceeded;
            }

            var payload = new byte[declared];
            Buffer.BlockCopy(buffer, at, payload, 0, (int)declared);
            at += (int)declared;

            var signature = new byte[Constants.SignatureLength];
            Buffer.BlockCopy(
                buffer, at, signature, 0, Constants.SignatureLength);
            at += Constants.SignatureLength;

            if (at != buffer.Length)
            {
                // Unreachable while the count check above holds, and kept so
                // that a future change to that arithmetic cannot silently
                // start accepting trailing bytes.
                return OwidParseStatus.MalformedEnvelope;
            }

            owid = Model.Owid.CreateForParser(
                version, domain, date, payload, signature);
            return OwidParseStatus.Parsed;
        }

        /// <summary>
        /// The creator domain, terminated by a zero byte and no longer than
        /// the published maximum.
        /// </summary>
        private static OwidParseStatus ReadDomain(
            byte[] buffer,
            ref int at,
            out string domain)
        {
            domain = string.Empty;
            var start = at;
            var limit = Math.Min(
                buffer.Length,
                start + Constants.MaximumDomainLength + 1);

            while (at < limit)
            {
                if (buffer[at] == 0)
                {
                    domain = Encoding.ASCII.GetString(
                        buffer, start, at - start);
                    at++;
                    return OwidParseStatus.Parsed;
                }
                at++;
            }

            // Either the buffer ended inside the domain, or the domain ran
            // past the maximum without terminating. The second is a domain
            // that cannot be valid rather than data that merely stopped, so
            // the two are reported differently.
            return at >= buffer.Length && at - start <= Constants.MaximumDomainLength
                ? OwidParseStatus.UnexpectedEnd
                : OwidParseStatus.InvalidDomainEncoding;
        }

        /// <summary>
        /// The creation date, whose width depends on the version.
        /// </summary>
        private static OwidParseStatus ReadDate(
            byte[] buffer,
            ref int at,
            OwidVersion version,
            out DateTime date)
        {
            date = Constants.BaseDate;
            if (version == OwidVersion.Version1)
            {
                if (Remaining(buffer, at) < 2)
                {
                    return OwidParseStatus.UnexpectedEnd;
                }
                var hours = (buffer[at] << 8) | buffer[at + 1];
                at += 2;
                date = Constants.BaseDate.AddHours(hours);
                return OwidParseStatus.Parsed;
            }

            if (Remaining(buffer, at) < sizeof(uint))
            {
                return OwidParseStatus.UnexpectedEnd;
            }
            var minutes = (uint)(
                buffer[at] |
                (buffer[at + 1] << 8) |
                (buffer[at + 2] << 16) |
                (buffer[at + 3] << 24));
            at += sizeof(uint);
            date = Constants.BaseDate.AddMinutes(minutes);
            return OwidParseStatus.Parsed;
        }

        private static long Remaining(byte[] buffer, int at)
        {
            return (long)buffer.Length - at;
        }
    }
}
