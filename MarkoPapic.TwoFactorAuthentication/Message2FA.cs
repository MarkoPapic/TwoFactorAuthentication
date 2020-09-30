using System;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Contains the functionality for message-based methods of 2-factor authentication (SMS, email...).
    /// </summary>
    public class Message2FA : TwoFactorAuthenticationBase
    {
        internal Message2FA(uint timeStep, ushort allowedVariance) : base(timeStep, allowedVariance) { }

        /// <summary>
        /// Generates a TOTP to be sent to the user.
        /// </summary>
        /// <param name="key">Base32 encoded string that is uniquely associated to the user.</param>
        /// <returns>Code to be sent to the user.</returns>
        public string GenerateTotp(string key)
        {

            byte[] secret = Base32.FromBase32(key);
            string code = this.totpService.GenerateTotp(secret);
            return code;
        }
    }
}
