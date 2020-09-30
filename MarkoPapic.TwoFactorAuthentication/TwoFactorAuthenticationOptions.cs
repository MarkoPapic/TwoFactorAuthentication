using System;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Used to configure the 2-factor authentication.
    /// </summary>
    public class TwoFactorAuthenticationOptions
    {
        /// <summary>
        /// Specifies the duration for which message-based TOTPs should be valid. Default is 300s.
        /// </summary>
        public uint MessageTotpDuration { get; set; } = 300;

        /// <summary>
        /// Allows up to the specified adjacent intervals to be checked when validating message-based TOTPs. This can make up for delays caused by latency or clock missmatch. Default is 0.
        /// </summary>
        public ushort MessageTotpVarianceAllowed { get; set; } = 0;

        /// <summary>
        /// Allows up to the specified adjacent intervals to be checked when validating authenticator app TOTPs. This can make up for delays caused by latency or clock missmatch. Default is 0.
        /// </summary>
        public ushort AuthenticatorTotpVarianceAllowed { get; set; } = 1;
    }
}
