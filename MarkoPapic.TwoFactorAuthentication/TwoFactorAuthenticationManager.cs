
using Microsoft.Extensions.Options;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Contains functionality for 2-factor authentication.
    /// </summary>
    public class TwoFactorAuthenticationManager
    {
        private readonly TwoFactorAuthenticationOptions options;
        private AuthenticatorApp2FA _authenticatorApp;
        private Message2FA _message;

        /// <summary>
        /// Creates an instance of <c>TwoFactorAuthenticationManager</c>.
        /// </summary>
        public TwoFactorAuthenticationManager()
        {
            this.options = new TwoFactorAuthenticationOptions();
        }

        /// <summary>
        /// Creates an instance of <c>TwoFactorAuthenticationManager</c>.
        /// </summary>
        /// <param name="options">Options used to configure the <c>TwoFactorAuthenticationManager</c>.</param>
        public TwoFactorAuthenticationManager(TwoFactorAuthenticationOptions options)
        {
            this.options = options;
        }

        /// <summary>
        /// Creates an instance of <c>TwoFactorAuthenticationManager</c>.
        /// </summary>
        /// <param name="options">Options used to configure the <c>TwoFactorAuthenticationManager</c>.</param>
        public TwoFactorAuthenticationManager(IOptions<TwoFactorAuthenticationOptions> options)
        {
            this.options = options.Value;
        }

        /// <summary>
        /// Used for Authenticator app method of 2-factor authentication.
        /// </summary>
        public AuthenticatorApp2FA AuthenticatorApp
        {
            get
            {
                if (this._authenticatorApp == null)
                    this._authenticatorApp = new AuthenticatorApp2FA(this.options.AuthenticatorTotpVarianceAllowed);
                return this._authenticatorApp;
            }
        }

        /// <summary>
        /// Used for message-based methods of 2-factor authentication (SMS, email...).
        /// </summary>
        public Message2FA Message
        {
            get
            {
                if (this._message == null)
                    this._message = new Message2FA(this.options.MessageTotpDuration, this.options.MessageTotpVarianceAllowed);
                return this._message;
            }
        }
    }
}
