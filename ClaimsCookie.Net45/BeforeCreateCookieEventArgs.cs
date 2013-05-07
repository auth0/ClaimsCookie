namespace ClaimsCookie
{
    using System;
    using System.Security.Claims;

    public class BeforeCreateCookieEventArgs : EventArgs
    {
        public ClaimsPrincipal Principal { get; set; }
    }
}
