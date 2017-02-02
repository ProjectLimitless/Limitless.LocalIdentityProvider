/** 
* This file is part of Project Limitless.
* Copyright © 2016 Donovan Solms.
* Project Limitless
* https://www.projectlimitless.io
* 
* Project Limitless is free software: you can redistribute it and/or modify
* it under the terms of the Apache License Version 2.0.
* 
* You should have received a copy of the Apache License Version 2.0 with
* Project Limitless. If not, see http://www.apache.org/licenses/LICENSE-2.0.
*/

using System;

namespace Limitless.LocalIdentityProvider
{
    /// <summary>
    /// The JWT token structure.
    /// </summary>
    public class LocalIdentityToken
    {
        /// <summary>
        /// The subject.
        /// </summary>
        public string sub { get; set; }
        /// <summary>
        /// Expiration time.
        /// </summary>
        public long exp { get; set; }
        /// <summary>
        /// The issuer.
        /// </summary>
        public string iss { get; set; }
        /// <summary>
        /// The audience.
        /// </summary>
        public string aud { get; set; }
        /// <summary>
        /// The user's name.
        /// </summary>
        public string name { get; set; }
        /// <summary>
        /// The user's ID.
        /// </summary>
        public int uid { get; set; }
    }
}
