// JitPatcher/NativeMethods.cs
using System;

namespace JitPatcher
{
    // Copied from JitUnpacker-Framework/NativeMethods.cs
    // Only include what JitMethodBodyReader.CreateCilBody actually needs if you adapt it,
    // or the full structs if you use it as-is.

    [Flags]
    internal enum CORINFO_EH_CLAUSE_FLAGS // Assuming this name from original, adjust if different
    {
        CORINFO_EH_CLAUSE_NONE = 0,
        CORINFO_EH_CLAUSE_FILTER = 0x0001,
        CORINFO_EH_CLAUSE_FINALLY = 0x0002,
        CORINFO_EH_CLAUSE_FAULT = 0x0004,
        // ... other flags if they were present and used
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    internal struct CORINFO_EH_CLAUSE
    {
        public CORINFO_EH_CLAUSE_FLAGS Flags;
        public uint TryOffset;
        public uint TryLength;
        public uint HandlerOffset;
        public uint HandlerLength;
        public uint ClassTokenOrFilterOffset;
    }
}