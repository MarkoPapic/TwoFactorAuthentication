using System;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Contains the shared functionality for 2-factor authentication.
    /// </summary>
    public abstract class TwoFactorAuthenticationBase
    {
        internal readonly TotpService totpService;
        /// <summary>
        /// Number of adjacent intervals to be checked.
        /// </summary>
        protected readonly ushort allowedVariance;

        internal TwoFactorAuthenticationBase(uint timeStep, ushort allowedVariance)
        {
            this.totpService = new TotpService(timeStep);
            this.allowedVariance = allowedVariance;
        }

        /// <summary>
        /// Valiates a TOTP.
        /// </summary>
        /// <param name="key">Key associated to the account.</param>
        /// <param name="code">TOTP.</param>
        /// <returns>Boolean value indicating whether given TOTP is valid.</returns>
        public bool ValidateCode(string key, string code)
        {
            byte[] keyBytes = Base32.FromBase32(key);
            bool isValid = this.totpService.ValidateTotp(keyBytes, code, this.allowedVariance);
            return isValid;
        }
    }
}
