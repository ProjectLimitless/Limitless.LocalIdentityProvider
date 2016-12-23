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

using Limitless.Runtime.Types;

namespace Limitless.LocalIdentityProvider
{
    /// <summary>
    /// The user object for local-only users.
    /// </summary>
    public class LocalUser : BaseUser
    {
        /// <summary>
        /// TODO: Testing
        /// </summary>
        public string IDNumber { get; set; }

        /// <summary>
        /// Standard constructor with the username.
        /// </summary>
        /// <param name="username"></param>
        public LocalUser(string username) : base(username)
        {
        }
    }
}
