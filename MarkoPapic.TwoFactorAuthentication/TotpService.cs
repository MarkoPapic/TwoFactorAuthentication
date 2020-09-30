using System;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace MarkoPapic.TwoFactorAuthentication
{
    internal class TotpService
    {
		const uint NUMBER_OF_DIGITS = 6;
		private static readonly DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		private static readonly Encoding encoding = new UTF8Encoding(false, true);
		private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
		private readonly uint timeStep;

		internal TotpService(uint timeStep)
		{
			this.timeStep = timeStep;
		}

		internal byte[] GenerateRandomKey(int numberOfBytes = 20)
		{
			byte[] bytes = new byte[numberOfBytes];
			rng.GetBytes(bytes);
			return bytes;
		}

		internal string GenerateTotp(byte[] secret, string modifier = null)
		{
			if (secret == null)
			{
				throw new ArgumentNullException(nameof(secret));
			}

			ulong iterationNumber = this.GetCurrentIteration();
			using (HMACSHA1 hashAlgorithm = new HMACSHA1(secret))
			{
				return GenerateTotp(hashAlgorithm, (ulong)((long)iterationNumber), modifier);
			}
		}

		internal bool ValidateTotp(byte[] secret, string code, ushort allowedVariance = 1, string modifier = null)
		{
			if (secret == null)
				throw new ArgumentNullException(nameof(secret));

			ulong iterationNumber = this.GetCurrentIteration();
			using (HMACSHA1 hashAlgorithm = new HMACSHA1(secret))
			{
				string computedTotp = GenerateTotp(hashAlgorithm, (ulong)((long)iterationNumber), modifier);
				if (computedTotp == code)
					return true;

				if (allowedVariance > 0)
				{
					for (var i = 1; i <= allowedVariance; i++)
					{
						computedTotp = GenerateTotp(hashAlgorithm, (ulong)((long)iterationNumber + i), modifier);
						if (computedTotp == code)
							return true;

						computedTotp = GenerateTotp(hashAlgorithm, (ulong)((long)iterationNumber - i), modifier);
						if (computedTotp == code)
							return true;
					}
				}
			}

			return false;
		}

		private static string GenerateTotp(HashAlgorithm hashAlgorithm, ulong iterationNumber, string modifier) // modifier is used as some kind of salt
		{
			// See https://tools.ietf.org/html/rfc4226
			var timestepAsBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)iterationNumber));
			var hash = hashAlgorithm.ComputeHash(ApplyModifier(timestepAsBytes, modifier));

			// Generate DT string
			var offset = hash[hash.Length - 1] & 0xf;
			var binaryCode = (hash[offset] & 0x7f) << 24
							 | (hash[offset + 1] & 0xff) << 16
							 | (hash[offset + 2] & 0xff) << 8
							 | (hash[offset + 3] & 0xff);

			int totpNumber = binaryCode % (int)Math.Pow(10, NUMBER_OF_DIGITS);
			string totp = totpNumber.ToString("D6", CultureInfo.InvariantCulture);

			return totp;
		}

		private ulong GetCurrentIteration()
		{
			double totalSeconds = (DateTime.UtcNow - unixEpoch).TotalSeconds;
			ulong counter = (ulong)Math.Floor(totalSeconds / this.timeStep);
			return counter;
		}

		private static byte[] ApplyModifier(byte[] input, string modifier)
		{
			if (string.IsNullOrEmpty(modifier))
				return input;

			byte[] modifierBytes = encoding.GetBytes(modifier);
			byte[] combined = new byte[checked(input.Length + modifierBytes.Length)];
			Buffer.BlockCopy(input, 0, combined, 0, input.Length);
			Buffer.BlockCopy(modifierBytes, 0, combined, input.Length, modifierBytes.Length);
			return combined;
		}
	}
}
