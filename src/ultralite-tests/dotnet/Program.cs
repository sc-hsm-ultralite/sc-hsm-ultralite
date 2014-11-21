//
// SmartCard-HSM Ultra-Light Library Test Application
//
// Copyright (c) 2013. All rights reserved.
//
// This program is free software: you can redistribute it and/or modify 
// it under the terms of the BSD 3-Clause License. You should have 
// received a copy of the BSD 3-Clause License along with this program. 
// If not, see <http://opensource.org/licenses/>
//
// @file Program.cs
// @author Keith Morgan
//

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

class Program
{	
	[DllImport("sc-hsm-ultralite.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
	static extern int sign_hash(string pin, string label, byte[] hash, int hashLen, out IntPtr cms);

	[DllImport("sc-hsm-ultralite.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
	static extern int release_template();

	[DllImport("sc-hsm-ultralite.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
	static extern void sha256_starts(byte[] ctx);

	[DllImport("sc-hsm-ultralite.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
	static extern void sha256_update(byte[] ctx, byte[] input, uint length);
	
	[DllImport("sc-hsm-ultralite.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
	static extern void sha256_finish(byte[] ctx, byte[] digest);

	static void Main(string[] args)
	{
		try {
			_Main(args);
		} catch (Exception ex) {
			Console.WriteLine("Uncaught Exception: " + ex);
		}
	}

	static void _Main(string[] args)
	{
		// Get path+filename of this executable (i.e. argv[0])
		string argv0 = Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName);

		// Check args
		if (args.Length < 2) {
			Console.WriteLine("Usage: pin label [count [wait-in-milliseconds]]\r\nSign this executable ({0}).", argv0);
			return;
		}

		// Parse optional args
		int count, wait;
		if (args.Length < 3 || !int.TryParse(args[2], out count))
			count = 1;
		if (args.Length < 4 || !int.TryParse(args[3], out  wait))
			wait  = 10000;

		// Create a SHA-256 hash of this executable
		byte[] buf  = File.ReadAllBytes(argv0);
#if MANAGED
		SHA256Managed sha256 = new SHA256Managed();
		byte[] hash = sha256.ComputeHash(buf, 0, buf.Length);
#else
		byte[] ctx  = new byte[104]; // 104 => sizeof(sha256_ctx)
		byte[] hash = new byte[ 32]; //  32 => 256-bit sha256
		sha256_starts(ctx);
		sha256_update(ctx, buf, (uint)buf.Length);
		sha256_finish(ctx, hash);
#endif

		// Sign the hash of this executable n times, where n = count
		try {
			for (int i = 0; i < count; i++) {
				if (i > 0 && count > 1) {
					Console.WriteLine("wait {0} milliseconds for next signature", wait);
					Thread.Sleep(wait);
				}
				IntPtr pCms;
				long start = Environment.TickCount;
				int  len   = sign_hash(args[0], args[1], hash, hash.Length, out pCms); 
				long end   = Environment.TickCount;
				Console.WriteLine("sign_hash returned: {0}, time used: {1} ms", len, end - start);
				if (len > 0) {
					byte[] cms = new byte[len];
					Marshal.Copy(pCms, cms, 0, cms.Length);
					File.WriteAllBytes(argv0 + ".p7s", cms);
				}
			}
		} finally {
			release_template();
		}
	}
}

