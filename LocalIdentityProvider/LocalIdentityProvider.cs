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
using Limitless.Runtime.Interfaces;
using Limitless.LocalIdentityProvider.Models;

namespace Limitless.LocalIdentityProvider
{
    /// <summary>
    /// Provides identity for local-only users.
    /// </summary>
    public class LocalIdentityProvider : IModule, IIdentityProvider
    {
        /// <summary>
        /// The logger.
        /// </summary>
        private ILogger _log;
        /// <summary>
        /// The database provider.
        /// </summary>
        private IDatabaseProvider _db;
        /// <summary>
        /// The local configuration.
        /// </summary>
        private LocalIdentityConfig _config;
        /// <summary>
        /// JWT secret key.
        /// </summary>
        private byte[] _key;

        /// <summary>
        /// Standard constructor with log.
        /// </summary>
        /// <param name="log">The logger to use</param>
        public LocalIdentityProvider(ILogger log, IDatabaseProvider db)
        {
            _log = log;
            _db = db;
            // TODO: Key needs to be from config
            _key = new byte[] { 112, 163, 236, 130, 140, 212, 109, 228, 219, 63, 15, 4, 136, 43, 239, 186 };
            _log.Debug("Created with log type '{0}'", _log.GetType());
            _log.Debug("Created with Database provider type '{0}'", _db.GetType());
        }

        //TODO: Move this module to a separate assembly?
        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interface.IModule.Configure"/>
        /// </summary>
        public void Configure(dynamic settings)
        {
            if (settings == null)
            {
                throw new NullReferenceException("Settings can not be null");
            }
            LocalIdentityConfig config = (LocalIdentityConfig)settings;
            _config = config;
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interface.IModule.GetConfigurationType"/>
        /// </summary>
        public Type GetConfigurationType()
        {
            return typeof(LocalIdentityConfig);
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interface.IIdentityProvider.ValidateToken"/>
        /// </summary>
        public BaseUser ValidateToken(string token)
        {
            try
            {
                var payload = Jose.JWT.Decode<LocalIdentityToken>(token, _key);
                var tokenExpires = DateTime.FromBinary(payload.exp);
                if (tokenExpires > DateTime.UtcNow)
                {
                    Users userModel = _db.QuerySingle<Users>(
                        @"SELECT * FROM users WHERE id = @0 AND isDeleted = 0",
                        new object[] { payload.uid }
                    );
                    if (userModel != null)
                    {
                        BaseUser user = new BaseUser(userModel.Username, true);
                        user.Name = userModel.FirstName;
                        user.Surname = userModel.LastName;
                        return user;
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
            return null;
        }

        /// <summary>
        /// Implemented from interface 
        /// <see cref="Limitless.Runtime.Interface.IIdentityProvider.Login"/>
        /// </summary>
        public BaseUser Login(string username, string password)
        {
            // TODO: Find a clean way to handle required parameters
            // TODO: Check null returns - could be better
            Users userModel = _db.QuerySingle<Users>(
                @"SELECT * FROM users WHERE username = @0 AND isDeleted = 0", 
                new object[] { username }
            );
            if (userModel == null)
            {
                return null;
            }
            if (BCrypt.Net.BCrypt.Verify(password, userModel.Password) == false)
            {
                return null;
            }

            // Generate access token
            LocalIdentityToken payload = new LocalIdentityToken();
            payload.aud = "limitless.local";
            payload.exp = DateTime.Now.AddDays(1).Ticks;
            payload.iss = "limitless.local";
            payload.name = $"{userModel.FirstName} {userModel.LastName}";
            payload.sub = "Local User";
            payload.uid = userModel.ID;
            // TODO: Change to GCM-based token
            string token = Jose.JWT.Encode(payload, _key, Jose.JwsAlgorithm.HS512);
            
            BaseUser user = new BaseUser(username, true);
            user.Name = userModel.FirstName;
            user.Surname = userModel.LastName;
            user.AccessToken = token;
            return user;
        }
    }
}
