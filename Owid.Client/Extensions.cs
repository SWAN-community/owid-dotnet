/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Owid.Client
{
    public static class Extensions
    {
		public static byte[] AsByteArray(this Model.Owid owid)
		{
			using (var stream = new MemoryStream())
			{
				using (var writer = new BinaryWriter(stream))
				{
					owid.ToBuffer(writer);
				}
				return stream.ToArray();
			}
		}

		public static string AsBase64(this Model.Owid owid)
		{
			return Convert.ToBase64String(owid.AsByteArray());
		}

		public static void EmptyToBuffer(BinaryWriter writer)
		{
			writer.Write((byte)OwidVersion.Empty);
		}

		public static void ToBuffer(this Model.Owid owid, BinaryWriter writer)
		{
			owid.ToBufferNoSignature(writer);
			WriteSignature(writer, owid.Signature);
		}

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
					return ReadDateV2(reader);
			}
			return null;
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

		private static byte[] ReadByteArray(BinaryReader reader)
		{
			var count = reader.ReadUInt32();
			return reader.ReadBytes((int)count);
		}

		private static void WriteByteArray(BinaryWriter writer, byte[] array)
		{
			writer.Write((uint)array.Length);
			writer.Write(array);
		}

		private static string ReadString(BinaryReader reader)
		{
			return ASCIIEncoding.ASCII.GetString(
				ReadBytes(reader, 0).ToArray());
		}

		private static IEnumerable<byte> ReadBytes(
			BinaryReader reader,
			byte stop)
		{
			byte value = stop;
			do
			{
				value = reader.ReadByte();
				if (value == stop)
				{
					break;
				}
				yield return value;
			} while (value != stop);
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
					owid.WriteDateV2(writer);
					return;
				default:
					throw new Exception("Version not supported");
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
