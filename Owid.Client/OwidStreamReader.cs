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
using System.IO;
using System.Text;
using Owid.Client.Model;

namespace Owid.Client
{
    /// <summary>
    /// Reads one OWID from a stream that may carry more after it.
    /// </summary>
    /// <remarks>
    /// This is the framed contract, and it differs from reading a whole buffer
    /// in exactly one place. A whole buffer knows where the envelope ends, so
    /// the declared payload must leave exactly the signature and nothing else.
    /// A stream does not: what follows may be the next envelope rather than
    /// rubbish, so this needs the declared payload and the signature to be
    /// present and says nothing at all about the rest.
    ///
    /// It reads forward only and never asks the stream for its length, so it
    /// works on a source that cannot answer that, and it reads the payload in
    /// fixed pieces rather than allocating from the declared count. A sender
    /// choosing that count must not be able to choose how much memory a reader
    /// takes before it has seen the bytes to justify it.
    ///
    /// Every read goes through the stream's own end of data signal rather than
    /// the helpers that throw at the end, because a stream ending early is an
    /// ordinary outcome here and not a fault.
    /// </remarks>
    internal static class OwidStreamReader
    {
        /// <summary>
        /// Bytes read at a time when collecting a payload, so that a declared
        /// count cannot decide the allocation before the data is there.
        /// </summary>
        private const int PieceLength = 4096;

        internal static OwidParseStatus TryRead(
            Stream stream,
            out Model.Owid? owid)
        {
            owid = null;
            if (stream == null)
            {
                return OwidParseStatus.MissingInput;
            }

            var first = stream.ReadByte();
            if (first < 0)
            {
                // The stream had nothing left, which is how a caller reading a
                // sequence of envelopes finds out it has reached the end.
                return OwidParseStatus.MissingInput;
            }

            var version = (OwidVersion)first;
            switch (version)
            {
                case OwidVersion.Version1:
                case OwidVersion.Version2:
                case OwidVersion.Version3:
                    break;
                case OwidVersion.Empty:
                    // An absent node. No value is handed back, and the one
                    // byte has already been taken from the stream, so a caller
                    // walking a run of frames reads the next one next.
                    return OwidParseStatus.AbsentNode;

                default:
                    return OwidParseStatus.UnsupportedVersion;
            }

            var domainStatus = ReadDomain(stream, out var domain);
            if (domainStatus != OwidParseStatus.Parsed)
            {
                return domainStatus;
            }

            var dateStatus = ReadDate(stream, version, out var date);
            if (dateStatus != OwidParseStatus.Parsed)
            {
                return dateStatus;
            }

            var lengthBytes = new byte[sizeof(uint)];
            if (ReadExactly(stream, lengthBytes, lengthBytes.Length) == false)
            {
                return OwidParseStatus.UnexpectedEnd;
            }
            var declared = (uint)(
                lengthBytes[0] |
                (lengthBytes[1] << 8) |
                (lengthBytes[2] << 16) |
                (lengthBytes[3] << 24));

            if (declared > Array.MaxLength)
            {
                return OwidParseStatus.ImplementationCapacityExceeded;
            }

            var payloadStatus = ReadCounted(stream, declared, out var payload);
            if (payloadStatus != OwidParseStatus.Parsed)
            {
                return payloadStatus;
            }

            var signature = new byte[Constants.SignatureLength];
            if (ReadExactly(
                    stream, signature, Constants.SignatureLength) == false)
            {
                // The stream ran out before the signature. That is data
                // stopping early rather than a declaration disagreeing with
                // data that is all present, and a caller reading from a source
                // still arriving needs to know whether waiting would help.
                return OwidParseStatus.UnexpectedEnd;
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
            Stream stream,
            out string domain)
        {
            domain = string.Empty;
            var buffer = new byte[Constants.MaximumDomainLength];
            var length = 0;
            while (length <= Constants.MaximumDomainLength)
            {
                var next = stream.ReadByte();
                if (next < 0)
                {
                    return OwidParseStatus.UnexpectedEnd;
                }
                if (next == 0)
                {
                    domain = Encoding.ASCII.GetString(buffer, 0, length);
                    return OwidParseStatus.Parsed;
                }
                if (length == Constants.MaximumDomainLength)
                {
                    // One byte past the maximum with no terminator, so this
                    // cannot be a valid domain however the rest reads.
                    return OwidParseStatus.InvalidDomainEncoding;
                }
                buffer[length] = (byte)next;
                length++;
            }
            return OwidParseStatus.InvalidDomainEncoding;
        }

        private static OwidParseStatus ReadDate(
            Stream stream,
            OwidVersion version,
            out DateTime date)
        {
            date = Constants.BaseDate;
            var width = version == OwidVersion.Version1 ? 2 : sizeof(uint);
            var buffer = new byte[width];
            if (ReadExactly(stream, buffer, width) == false)
            {
                return OwidParseStatus.UnexpectedEnd;
            }
            if (version == OwidVersion.Version1)
            {
                date = Constants.BaseDate.AddHours(
                    (buffer[0] << 8) | buffer[1]);
                return OwidParseStatus.Parsed;
            }
            var minutes = (uint)(
                buffer[0] |
                (buffer[1] << 8) |
                (buffer[2] << 16) |
                (buffer[3] << 24));
            date = Constants.BaseDate.AddMinutes(minutes);
            return OwidParseStatus.Parsed;
        }

        /// <summary>
        /// The payload, collected in fixed pieces so that nothing is sized by
        /// the declared count before the bytes to justify it have arrived.
        /// </summary>
        private static OwidParseStatus ReadCounted(
            Stream stream,
            uint count,
            out byte[] payload)
        {
            payload = Array.Empty<byte>();
            if (count == 0)
            {
                return OwidParseStatus.Parsed;
            }

            var collected = new byte[Math.Min(count, (uint)PieceLength)];
            var result = new MemoryStream();
            long left = count;
            while (left > 0)
            {
                var want = (int)Math.Min(collected.Length, left);
                if (ReadExactly(stream, collected, want) == false)
                {
                    // The stream ended inside the payload the sender declared.
                    // Data stopping early, not a disagreement.
                    return OwidParseStatus.UnexpectedEnd;
                }
                result.Write(collected, 0, want);
                left -= want;
            }
            payload = result.ToArray();
            return OwidParseStatus.Parsed;
        }

        /// <summary>
        /// Fills the first <paramref name="count"/> bytes of the buffer, or
        /// reports that the stream ended first. A stream may hand back fewer
        /// bytes than asked for without being at its end, so this loops rather
        /// than treating a short read as the end.
        /// </summary>
        private static bool ReadExactly(
            Stream stream,
            byte[] buffer,
            int count)
        {
            var at = 0;
            while (at < count)
            {
                var read = stream.Read(buffer, at, count - at);
                if (read <= 0)
                {
                    return false;
                }
                at += read;
            }
            return true;
        }
    }
}
