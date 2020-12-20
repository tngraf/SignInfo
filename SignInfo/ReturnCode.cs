// ---------------------------------------------------------------------------
// <copyright file="ReturnCode.cs" company="Tethys">
//   Copyright (C) 2020 T. Graf
// </copyright>
//
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.
// ---------------------------------------------------------------------------

namespace SignInfo
{
    /// <summary>
    /// Application return codes.
    /// </summary>
    public enum ReturnCode
    {
        /// <summary>
        /// Internal application error.
        /// </summary>
        InternalError = -99,

        /// <summary>
        /// File not found.
        /// </summary>
        FileNotFound = -2,

        /// <summary>
        /// Insufficient or wrong arguments.
        /// </summary>
        InsufficientArguments = -1,

        /// <summary>
        /// All operations succeeded, file is signed and signature is verified
        /// </summary>
        FileSignedAndVerified = 0,

        /// <summary>
        /// File is not signed.
        /// </summary>
        FileNotSigned = 1,

        /// <summary>
        /// File is signed, but signature cannot get verified.
        /// </summary>
        FileSignatureNotVerified = 2,
    } // ReturnCode
}
