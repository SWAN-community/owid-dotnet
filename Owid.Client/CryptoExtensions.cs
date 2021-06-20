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

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Owid.Client
{
    public static class CryptoExtensions
    {
		/// <summary>
		/// Handlers used with HTTP clients to automatically decompress any
		/// compressed data streams.
		/// </summary>
		private static readonly HttpClientHandler _handler =
			new HttpClientHandler()
			{
				AutomaticDecompression =
					DecompressionMethods.GZip | DecompressionMethods.Deflate
			};

		public static async Task<bool> VerifyAsync(this Model.Owid owid)
		{
			using (var rsa = await owid.GetPublicKey("https"))
			{
				return await owid.VerifyAsync(rsa, Constants.Empty);
			}
		}

		public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			RSACryptoServiceProvider rsa)
        {
			return await owid.VerifyAsyncWithOthers(rsa, Constants.Empty);
		}

		public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			params Model.Owid[] others)
		{
			using (var rsa = await owid.GetPublicKey("https"))
			{
				return await owid.VerifyAsyncWithOthers(rsa, others);
			}
		}

		public static async Task<bool> VerifyAsync(
			this Model.Owid owid,
			RSACryptoServiceProvider rsa,
			params Model.Owid[] others)
        {
			return await owid.VerifyAsyncWithOthers(rsa, others);
		}

		public static Task<bool> VerifyAsyncWithOthers(
			this Model.Owid owid,
			RSACryptoServiceProvider rsa,
			Model.Owid[] others)
		{
			var data = owid.GetDataForCrypto(others);
			return Task.Run(() => rsa.VerifyData(
				data,
				owid.Signature,
				HashAlgorithmName.SHA256,
				RSASignaturePadding.Pkcs1));
		}

		/// <summary>
		/// Adds the fields from this OWID to the byte buffer without the 
		/// signature. Adds all the bytes of the others to the data.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="others"></param>
		/// <returns></returns>
		internal static byte[] GetDataForCrypto(
			this Model.Owid owid, 
			Model.Owid[] others)
        {
			using(var ms = new MemoryStream())
            {
				using (var writer = new BinaryWriter(ms))
				{
					owid.ToBufferNoSignature(writer);
					foreach(var other in others)
                    {
						other.ToBuffer(writer);
                    }
				}
				return ms.ToArray();
			}
        }

		/// <summary>
		/// Gets the public key for the owid.
		/// </summary>
		/// <param name="owid"></param>
		/// <param name="scheme"></param>
		/// <returns></returns>
		private static async Task<RSACryptoServiceProvider> GetPublicKey(
			this Model.Owid owid,
			string scheme)
        {
            // Construct the URL to get the public key.
            UriBuilder u = new UriBuilder(
                scheme,
                owid.Domain);
            u.Path = @$"/owid/api/v{(byte)owid.Version}/public-key";
            u.Query = "format=pkcs";

            // Create the RSA provider with the public key associated with the
			// OWID.
            var rsaKey = new RSACryptoServiceProvider();
            rsaKey.ImportFromPem(await GetPublicKey(u.Uri));
            return rsaKey;
        }

		/// <summary>
		/// Get the public key from the domain contained in the OWID.
		/// </summary>
		/// <param name="u"></param>
		/// <returns></returns>
        private static async Task<string> GetPublicKey(Uri u)
        {
            return await new HttpClient(_handler).GetStringAsync(u);
        }
    }
}
