// ---------------------------------------------------------------------------
// <copyright file="Program.cs" company="Tethys">
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
    using System;

    /// <summary>
    /// Main class of the application.
    /// </summary>
    public class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        /// <remarks>
        /// Application return codes:
        /// 0  => all operations succeeded, file is signed and signature is verified
        /// -1 => insufficient or wrong arguments
        /// -2 => file not found
        /// 1  => file is not signed
        /// 2  => file is signed, but signature cannot get verified
        /// </remarks>
        public static int Main(string[] args)
        {
            try
            {
                var prog = new SignInfo();
                return prog.Run(args);
            }
            catch (Exception ex)
            {
                var bak = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Severe internal error: " + ex.Message);
                Console.ForegroundColor = bak;
                return (int)ReturnCode.InternalError;
            } // catch
        } // Main()
    } // Program
}
