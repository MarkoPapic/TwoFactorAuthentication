using System;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Contains the functionality for Authenticator app method of 2-factor authentication.
    /// </summary>
    public class AuthenticatorApp2FA : TwoFactorAuthenticationBase
    {
        private const int TIME_STEP = 30;

        internal AuthenticatorApp2FA(ushort allowedVariance) : base(TIME_STEP, allowedVariance) { }

        /// <summary>
        /// Generates a new key for the account. This key should be entered in an authenticator app.
        /// </summary>
        /// <returns></returns>
        public string GenerateKey()
        {
            byte[] secretBytes = this.totpService.GenerateRandomKey();
            string secretString = Base32.ToBase32(secretBytes);
            return secretString;
        }
    }
}
