using System;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
// dnlib.IO is not directly used for ByteArrayDataReaderFactory in this version of the logic
// but might be needed if JitMethodBodyReader or other components rely on it internally.

namespace JitPatcher // Namespace remains JitPatcher as per existing structure
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: JitUnpacker <protected_files_directory> <json_data_path>");
                Console.WriteLine("Example: JitUnpacker C:\\MyProtectedFiles dump.json");
                return;
            }

            string protectedFilesDirectory = args[0];
            string jsonDataPath = args[1];

            if (!Directory.Exists(protectedFilesDirectory))
            {
                Console.Error.WriteLine($"Error: Protected files directory not found: {protectedFilesDirectory}");
                return;
            }
            if (!File.Exists(jsonDataPath))
            {
                Console.Error.WriteLine($"Error: JSON data file not found: {jsonDataPath}");
                return;
            }

            Console.WriteLine($"Reading JSON data: {jsonDataPath}");
            JitDumpInfo jitDumpInfo = null;
            try
            {
                string jsonData = File.ReadAllText(jsonDataPath);
                jitDumpInfo = JsonSerializer.Deserialize<JitDumpInfo>(jsonData, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deserializing JSON data: {ex.Message}");
                return;
            }

            if (jitDumpInfo == null || jitDumpInfo.ModulesInfo == null || !jitDumpInfo.ModulesInfo.Any())
            {
                Console.Error.WriteLine("Error: JSON data is invalid, contains no module information, or failed to deserialize correctly.");
                return;
            }

            List<string> filesInProtectedDir = Directory.GetFiles(protectedFilesDirectory).ToList();
            if (!filesInProtectedDir.Any())
            {
                Console.WriteLine($"No files found in directory: {protectedFilesDirectory}");
                return;
            }
            Console.WriteLine($"Found {filesInProtectedDir.Count} files in the protected directory.\n");

            foreach (var moduleInfo in jitDumpInfo.ModulesInfo)
            {

                string jsonAbsoluteModuleName = moduleInfo.ModuleName; // This is an absolute path from JSON
                string fileToProcess = null;

                // Find the corresponding file in the protected directory
                foreach (string filePathInDir in filesInProtectedDir)
                {
                    string fileName = Path.GetFileName(filePathInDir);
                    // Check if the absolute path from JSON contains the filename from the directory
                    if (jsonAbsoluteModuleName.IndexOf(fileName, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        fileToProcess = filePathInDir;
                        Console.WriteLine($"Found match: JSON module '{jsonAbsoluteModuleName}' corresponds to file '{fileToProcess}'.");
                        break;
                    }
                }

                if (fileToProcess == null)
                {
                    Console.WriteLine($"Warning: No file in directory '{protectedFilesDirectory}' found that matches JSON module name '{jsonAbsoluteModuleName}'. Skipping this module.");
                    continue;
                }

                Console.WriteLine($"Loading base assembly: {fileToProcess}");
                ModuleDefMD moduleDef = null;
                try
                {
                    moduleDef = ModuleDefMD.Load(fileToProcess);

                    Console.WriteLine($"Processing {moduleInfo.MethodsInfo.Count} methods from JSON for module: {moduleDef.Name}");
                    int patchedMethodsCount = 0;

                    foreach (MethodDumpInfo methodInfo in moduleInfo.MethodsInfo)
                    {
                        // Resolve method using only the RID part of the token.
                        // The type part (0x06000000 for MethodDef) is implied.
                        MethodDef methodDef = moduleDef.ResolveMethod(methodInfo.MethodToken & 0x00FFFFFF);
                        if (methodDef == null)
                        {
                            Console.Error.WriteLine($"Warning: Could not resolve method token 0x{methodInfo.MethodToken:X8} in {moduleDef.Name}. Skipping.");
                            continue;
                        }

                        Console.WriteLine($"Patching method: {methodDef.FullName} (Token: 0x{methodInfo.MethodToken:X8})");

                        try
                        {
                            methodDef.FreeMethodBody(); // Clear existing body, if any

                            if (string.IsNullOrEmpty(methodInfo.ILBytes))
                            {
                                methodDef.Body = null;
                                Console.WriteLine($"  Method has no IL in JSON. Cleared body.");
                                methodDef.ImplAttributes &= ~MethodImplAttributes.IL;
                                methodDef.ImplAttributes |= MethodImplAttributes.Runtime; // Or Abstract, Native etc.
                                methodDef.RVA = 0;
                                continue;
                            }

                            string ilHex = methodInfo.ILBytes;
                            byte[] ilBytes = Enumerable.Range(0, ilHex.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(ilHex.Substring(x, 2), 16))
                                     .ToArray();

                            byte[] localsSigBytes = null;
                            if (!string.IsNullOrEmpty(methodInfo.LocalsSignatureBytes))
                            {
                                string localsHex = methodInfo.LocalsSignatureBytes;
                                localsSigBytes = Enumerable.Range(0, localsHex.Length)
                                             .Where(x => x % 2 == 0)
                                             .Select(x => Convert.ToByte(localsHex.Substring(x, 2), 16))
                                             .ToArray();
                            }


                            CORINFO_EH_CLAUSE[] ehClausesForReader = null;
                            if (methodInfo.ExceptionHandlers != null && methodInfo.ExceptionHandlers.Any())
                            {
                                ehClausesForReader = methodInfo.ExceptionHandlers.Select(ehi => new CORINFO_EH_CLAUSE
                                {
                                    Flags = (CORINFO_EH_CLAUSE_FLAGS)ehi.HandlerType,
                                    TryOffset = ehi.TryStartOffset,
                                    TryLength = ehi.TryEndOffset - ehi.TryStartOffset,
                                    HandlerOffset = ehi.HandlerStartOffset,
                                    HandlerLength = ehi.HandlerEndOffset - ehi.HandlerStartOffset,
                                    ClassTokenOrFilterOffset = ehi.CatchTypeTokenOrFilterOffset
                                }).ToArray();
                            }

                            var bodyReader = new JitMethodBodyReader(moduleDef, methodDef.Parameters)
                            {
                                TokenResolver = (code, token) => token
                            };

                            CilBody cilBody = bodyReader.CreateCilBody(ilBytes, methodInfo.MaxStack, localsSigBytes, ehClausesForReader);
                            methodDef.Body = cilBody;

                            methodDef.ImplAttributes &= ~(MethodImplAttributes.Native | MethodImplAttributes.Runtime | MethodImplAttributes.Unmanaged);
                            methodDef.ImplAttributes |= MethodImplAttributes.IL;
                            methodDef.RVA = 0;

                            patchedMethodsCount++;
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Error patching method {methodDef.FullName}: {ex.Message}");
                            Console.Error.WriteLine(ex.StackTrace);
                        }
                    }
                    Console.WriteLine($"Patched {patchedMethodsCount} methods in {moduleDef.Name}.");

                    // Construct output path for this specific module
                    string outputFileName = Path.GetFileNameWithoutExtension(fileToProcess) + ".fixed" + Path.GetExtension(fileToProcess);
                    string currentOutputAssemblyPath = Path.Combine(protectedFilesDirectory, outputFileName);

                    var writerOptions = new ModuleWriterOptions(moduleDef);
                    // writerOptions.Logger = DummyLogger.NoThrowInstance;
                    // writerOptions.MetadataOptions.Flags |= MetadataFlags.PreserveRids; 
                    // writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;

                    moduleDef.Write(currentOutputAssemblyPath, writerOptions);
                    Console.WriteLine($"Successfully saved patched assembly: {currentOutputAssemblyPath}\n");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error processing assembly {fileToProcess}: {ex.Message}");
                    Console.Error.WriteLine(ex.StackTrace);
                }
                finally
                {
                    moduleDef?.Dispose(); // Dispose the module after processing and saving
                }
            }
            Console.WriteLine("All specified modules processed.");
        }
    }
}