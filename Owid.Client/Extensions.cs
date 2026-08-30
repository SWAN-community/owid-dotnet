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

using Owid.Client.Model;
using System;
using System.IO;
using System.Text;

namespace Owid.Client
{
	/// <summary>
	/// Extensions methods for <see cref="Owid"/>.
	/// </summary>
    public static class Extensions
    {
		/// <summary>
		/// Converts <see cref="Owid"/> to byte array.
		/// </summary>
		/// <param name="owid"></param>
		/// <returns></returns>
		public static byte[] AsByteArray(this Model.Owid owid)
		{
			return ToExactBuffer(
				owid.GetByteCount(),
				owid,
				static (writer, o) => o.ToBuffer(writer));
		}

		/// <summary>
		/// The number of bytes <see cref="AsByteArray"/> returns for the
		/// OWID in its current state, being the version byte, the domain
		/// with its terminator, the date, the length-prefixed payload and
		/// the signature.
		/// </summary>
		/// <param name="owid"></param>
		/// <returns></returns>
		public static int GetByteCount(this Model.Owid owid)
		{
			int dateLength;
			switch (owid.Version)
			{
				case OwidVersion.Version1:
					dateLength = 2;
					break;
				case OwidVersion.Version2:
				case OwidVersion.Version3:
					dateLength = 4;
					break;
				default:
					throw new Exception(
						@$"OWID version '{owid.Version}' not supported");
			}
			return 1 +
				ASCIIEncoding.ASCII.GetByteCount(owid.Domain) + 1 +
				dateLength +
				4 + owid.Payload.Length +
				Constants.SignatureLength;
		}

		/// <summary>
		/// The bytes the signature covers, being the version, domain, date
		/// and payload. A caller that checks one OWID against several
		/// candidate public keys can build these bytes once and run the
		/// signature check per key, rather than rebuilding the same bytes
		/// for every attempt.
		/// </summary>
		/// <param name="owid"></param>
		/// <returns></returns>
		public static byte[] GetSignedBytes(this Model.Owid owid)
		{
			return ToExactBuffer(
				owid.GetSignedByteCount(),
				owid,
				static (writer, o) => o.ToBufferNoSignature(writer));
		}

		/// <summary>
		/// The number of bytes the signature covers, being everything
		/// <see cref="GetByteCount"/> counts except the signature itself.
		/// </summary>
		/// <param name="owid"></param>
		/// <returns></returns>
		public static int GetSignedByteCount(this Model.Owid owid)
		{
			return owid.GetByteCount() - Constants.SignatureLength;
		}

		/// <summary>
		/// Writes into a buffer of exactly the given size through a
		/// BinaryWriter, so every serialization shares one sizing and
		/// wrapping implementation. The buffer never grows and is returned
		/// without a final copy, and a wrong size fails loudly rather than
		/// truncating. The state parameter with static callers keeps the
		/// sharing free of closure allocations.
		/// </summary>
		internal static byte[] ToExactBuffer<TState>(
			int size,
			TState state,
			Action<BinaryWriter, TState> write)
		{
			var buffer = new byte[size];
			using (var stream = new MemoryStream(buffer))
			{
				using (var writer = new BinaryWriter(stream))
				{
					write(writer, state);
				}
			}
			return buffer;
		}

        /// <summary>
        /// Converts <see cref="Owid"/> to Base64-encoded string.
        /// </summary>
        /// <param name="owid"></param>
        /// <returns></returns>
        public static string AsBase64(this Model.Owid owid)
		{
			return Convert.ToBase64String(owid.AsByteArray());
		}

		/// <summary>
		/// Writes empty <see cref="Owid"/> to <paramref name="writer"/>.
		/// </summary>
		/// <param name="writer"></param>
		public static void EmptyToBuffer(BinaryWriter writer)
		{
			writer.Write((byte)OwidVersion.Empty);
		}

        /// <summary>
        /// Writes <paramref name="owid"/> to <paramref name="writer"/>
        /// </summary>
        /// <param name="owid"></param>
        /// <param name="writer"></param>
        public static void ToBuffer(this Model.Owid owid, BinaryWriter writer)
		{
			owid.ToBufferNoSignature(writer);
			WriteSignature(writer, owid.Signature);
		}

		/// <summary>
		/// Reads <see cref="Owid"/> data
		/// from <paramref name="reader"/>.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="reader"></param>
		/// <exception cref="Exception"></exception>
		public static void FromBuffer(
			this Model.Owid owid, 
			BinaryReader reader)
		{
			owid.Domain = ReadString(reader);
			var date = ReadDate(reader, owid.Version);
			if (date.HasValue == false)
			{
				throw new Exception("OWID must contain valid date");
			}
			owid.Date = date.Value;
			owid.Payload = ReadByteArray(reader);
			owid.Signature = ReadSignature(reader);
		}

		internal static void ToBufferNoSignature(
			this Model.Owid owid, 
			BinaryWriter writer)
		{
			writer.Write((byte)owid.Version);
			WriteString(writer, owid.Domain);
			owid.WriteDate(writer);
			WriteByteArray(writer, owid.Payload);
		}

		private static DateTime? ReadDate(
			BinaryReader reader,
			OwidVersion version)
		{
			switch (version)
			{
				case OwidVersion.Version1:
					return ReadDateV1(reader);
				case OwidVersion.Version2:
				case OwidVersion.Version3:
					return ReadDateV2(reader);
				default:
					throw new Exception(
						@$"OWID version '{version}' not supported");
			}
		}

		private static DateTime ReadDateV2(BinaryReader reader)
		{
			var m = reader.ReadUInt32();
			return Constants.BaseDate.AddMinutes(m);
		}

		private static DateTime ReadDateV1(BinaryReader reader)
		{
			var h = reader.ReadByte();
			var l = reader.ReadByte();
			var d = (int)h << 8 | (int)l;
			return Constants.BaseDate.AddHours(d);
		}

		/// <summary>
		/// Reads the length-prefixed payload. The count is whatever the
		/// sender declared, so it is checked against the bytes actually
		/// present before anything is sized by it. A valid OWID is the
		/// declared payload followed by the signature and nothing else, so
		/// the count must equal the bytes remaining less the signature
		/// length, and any other count is refused here. Until 27 August
		/// 2026 the count went straight to ReadBytes, which allocates the
		/// whole count before reading, so a 22 character identifier that
		/// declared 64 MiB cost 64 MiB of allocation per request before
		/// failing on its missing signature.
		/// </summary>
		private static byte[] ReadByteArray(BinaryReader reader)
		{
			var count = reader.ReadUInt32();
			var stream = reader.BaseStream;
			if (stream.CanSeek)
			{
				var remaining = stream.Length - stream.Position;
				var expected = (long)count + Constants.SignatureLength;
				if (remaining != expected)
				{
					throw new Exception(
						$@"OWID payload length '{count}' does not match the " +
						$@"'{remaining}' bytes present, of which the final " +
						$@"'{Constants.SignatureLength}' must be the signature");
				}
				return reader.ReadBytes((int)count);
			}
			return ReadCounted(reader, count);
		}

		/// <summary>
		/// The payload from a stream whose length cannot be asked for,
		/// read in bounded pieces so nothing is allocated from the
		/// declared count alone. The result is exactly the declared count
		/// or the read is refused, and the signature check that follows
		/// refuses a stream that then ends short.
		/// </summary>
		private static byte[] ReadCounted(BinaryReader reader, uint count)
		{
			const int Piece = 4096;
			using (var collected = new MemoryStream())
			{
				var piece = new byte[Piece];
				long left = count;
				while (left > 0)
				{
					var read = reader.Read(
						piece, 0, (int)Math.Min(Piece, left));
					if (read == 0)
					{
						throw new Exception(
							$@"OWID payload length '{count}' exceeds the " +
							"bytes present");
					}
					collected.Write(piece, 0, read);
					left -= read;
				}
				return collected.ToArray();
			}
		}

		private static void WriteByteArray(BinaryWriter writer, byte[] array)
		{
			writer.Write((uint)array.Length);
			writer.Write(array);
		}

		/// <summary>
		/// Reads the creator domain, being the ASCII bytes up to the zero
		/// terminator. The terminator is whatever the sender put there, so
		/// the walk stops at Constants.MaximumDomainLength rather than at
		/// the end of the buffer, and a domain that is longer than that, or
		/// that has no terminator inside it, is refused without reading any
		/// further. Until 30 August 2026 a missing or corrupted terminator
		/// sent the walk to the end of the buffer and collected every byte
		/// it passed, so the work a hostile envelope could ask for grew
		/// with the bytes it sent rather than being fixed by the published
		/// maximum for a domain.
		/// </summary>
		private static string ReadString(BinaryReader reader)
		{
			var domain = new byte[Constants.MaximumDomainLength];
			var length = 0;
			while (length < Constants.MaximumDomainLength)
			{
				var value = reader.ReadByte();
				if (value == 0)
				{
					return ASCIIEncoding.ASCII.GetString(domain, 0, length);
				}
				domain[length] = value;
				length++;
			}
			if (reader.ReadByte() != 0)
			{
				throw new Exception(
					"OWID domain is longer than the " +
					$@"'{Constants.MaximumDomainLength}' characters a domain " +
					"can have, or is missing its terminator");
			}
			return ASCIIEncoding.ASCII.GetString(domain, 0, length);
		}

		private static void WriteString(BinaryWriter writer, string value)
		{
			writer.Write(ASCIIEncoding.ASCII.GetBytes(value));
			writer.Write((byte)0);
		}

		private static void WriteDate(
			this Model.Owid owid, 
			BinaryWriter writer)
		{
			switch (owid.Version)
			{
				case OwidVersion.Version1:
					owid.WriteDateV1(writer);
					return;
				case OwidVersion.Version2:
				case OwidVersion.Version3:
					owid.WriteDateV2(writer);
					return;
				default:
					throw new Exception(
						@$"OWID version '{owid.Version}' not supported");
			}
		}

		private static void WriteDateV1(
			this Model.Owid owid, 
			BinaryWriter writer)
		{
			var i = (ushort)(owid.Date - Constants.BaseDate).TotalHours;
			writer.Write((byte)(i >> 8));
			writer.Write((byte)(i & 0x00FF));
		}

		private static void WriteDateV2(
			this Model.Owid owid, 
			BinaryWriter writer)
		{
			writer.Write((uint)(owid.Date - Constants.BaseDate).TotalMinutes);
		}

		private static byte[] ReadSignature(BinaryReader reader)
		{
			var signature = reader.ReadBytes(Constants.SignatureLength);
			if (Constants.SignatureLength != signature.Length)
			{
				throw new Exception(
					$@"Signature length '{signature.Length}' not " +
					$@"compaitable with '{Constants.SignatureLength}' OWID " +
					"signature length");
			}
			return signature;
		}

		private static void WriteSignature(BinaryWriter writer, byte[] signature)
		{
			if (Constants.SignatureLength != signature.Length)
			{
				throw new Exception(
					$@"Provided signature length '{signature.Length}' not " +
					$@"compaitable with '{Constants.SignatureLength}' OWID " +
					"signature length");
			}
			writer.Write(signature);
		}
	}
}
