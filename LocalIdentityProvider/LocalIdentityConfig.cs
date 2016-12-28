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
    /// The configuration for local identities.
    /// </summary>
    public class LocalIdentityConfig
    {
        /// <summary>
        /// The cost (or work factor) of the bcrypt hash.
        /// </summary>
        public int BCryptCost { get; set; }
    }
}
