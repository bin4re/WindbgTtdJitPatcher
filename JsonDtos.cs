using System.Collections.Generic;

// Re-define or ensure JitExtractor uses integer values for enums that System.Text.Json can map
// or use JsonStringEnumConverter if JitExtractor outputs enum names as strings.

namespace JitPatcher
{
    public class JitDumpInfo
    {
        public List<ModuleDumpInfo> ModulesInfo { get; set; }
    }
    public class ModuleDumpInfo
    {
        public string ModuleName { get; set; }
        public List<MethodDumpInfo> MethodsInfo { get; set; }
    }
    public class MethodDumpInfo
    {
        public string MethodName { get; set; }
        public uint MethodToken { get; set; }
        public string ILBytes { get; set; } 
        public ushort MaxStack { get; set; }
        public string LocalsSignatureBytes { get; set; } 
        public List<ExceptionHandlerInfo> ExceptionHandlers { get; set; } = new List<ExceptionHandlerInfo>();
    }

    public class ExceptionHandlerInfo
    {
        public int  HandlerType { get; set; }
        public uint TryStartOffset { get; set; }
        public uint TryEndOffset { get; set; } 
        public uint HandlerStartOffset { get; set; }
        public uint HandlerEndOffset { get; set; } 
        public uint CatchTypeTokenOrFilterOffset { get; set; }
    }

}