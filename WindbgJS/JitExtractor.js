//.scriptrun JitExtractor.js
"use strict"

function initializeScript()
{
    return [new host.apiVersionSupport(1, 9)];
}

class Windbg{
    static log = x => host.diagnostics.debugLog(`${x}\n`)

    static show = x => {
        for (var line of x) {
            Windbg.log(line); 
        }
    }

    static system = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x)

    static getUint32(addr){
        return host.memory.readMemoryValues(addr, 1, 4)[0]
    }

    static getBytesArr(addr,size){
        return host.memory.readMemoryValues(addr, size, 1)
    }

    static getRegVal(reg){
        return host.currentThread.Registers.User[reg]
    }
}

function ArrToDatView(arr){
    var buffer = new ArrayBuffer(arr.length);
    var uint8Array = new Uint8Array(buffer);
    arr.forEach((value, index) => {
        uint8Array[index] = value;
    });

    return new DataView(buffer);
}

function ArrayToHexStr(uint8Array) {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function WriteToFile(path,data) {
    var logFile;
    if (host.namespace.Debugger.Utility.FileSystem.FileExists(path)) {
        logFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(path, "CreateNew");
    } else {
        logFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(path);
    }
    var textWriter = host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(logFile, "Utf8");
    try {
            textWriter.WriteLine(data)
    } finally {
        logFile.Close();
    }
}

class MethodInfo{
    constructor(dataView, offset = 0){
        this.method_handle = dataView.getUint32(offset, true);
        this.module_handle = dataView.getUint32(offset + 4, true);
        this.ilcode_addr =  dataView.getUint32(offset + 8, true);
        this.ilcode_size =  dataView.getUint32(offset + 12, true);
        this.max_stack =  dataView.getUint32(offset + 16, true);
        this.eh_count =  dataView.getUint32(offset + 20, true);
    }
}

class EHClauseInfo{
        constructor(dataView, offset = 0) {
        this.HandlerType = dataView.getUint32(offset, true);
        this.TryOffset = dataView.getUint32(offset + 4, true);
        this.TryLength = dataView.getUint32(offset + 8, true);
        this.HandlerOffset = dataView.getUint32(offset + 12, true);
        this.HandlerLength = dataView.getUint32(offset + 16, true);
        this.CatchTypeTokenOrFilterOffset = dataView.getUint32(offset + 20, true);
    }
}

const FilterTargets = {
    MODULE: "module",
    METHOD: "method"
};

const FilterTypes = {
    INCLUDE: "include",
    EXCLUDE: "exclude"
};

const FilterMatchTypes = {
    CONTAINS: "contains",
    EXACT: "exact",
    STARTS_WITH: "startsWith",
    ENDS_WITH: "endsWith"
};

function matchesPattern(text, pattern, matchType = "contains") {
    if (text === null || text === undefined || pattern === null || pattern === undefined) return false;
    switch (matchType.toLowerCase()) {
        case "exact":
            return text === pattern;
        case "startswith":
            return text.startsWith(pattern);
        case "endswith":
            return text.endsWith(pattern);
        case "contains":
        default:
            return text.includes(pattern);
    }
}

function applyFilterRules(moduleName, methodName, rules) {
    if (!rules || rules.length === 0) {
        return true; // 没有规则，默认处理
    }
    
    const moduleRules = rules.filter(r => r.target === "module");
    const methodRules = rules.filter(r => r.target === "method");
    
    // --- 处理模块规则 ---
    // 1. 检查排除规则 (Exclude rules have higher precedence)
    for (const rule of moduleRules) {
        if (rule.type === "exclude" && matchesPattern(moduleName, rule.pattern, rule.matchType)) {
            Windbg.log(`Filter: Module '${moduleName}' excluded by rule: ${JSON.stringify(rule)}`);
            return false; // 模块被排除，直接返回 false
        }
    }

    // 2. 检查包含规则 (If include rules exist, at least one must match)
    const moduleIncludeRules = moduleRules.filter(r => r.type === "include");
    if (moduleIncludeRules.length > 0) {
        let matchedModuleInclude = false;
        for (const rule of moduleIncludeRules) {
            if (matchesPattern(moduleName, rule.pattern, rule.matchType)) {
                matchedModuleInclude = true;
                break;
            }
        }
        if (!matchedModuleInclude) {
            Windbg.log(`Filter: Module '${moduleName}' not included by any module 'include' rule.`);
            return false; // 模块未被任何包含规则匹配，返回 false
        }
    }
    // 如果执行到这里，模块通过了模块规则的检查（或没有模块规则）

    // --- 处理方法规则 ---
    // 1. 检查排除规则
    for (const rule of methodRules) {
        if (rule.type === "exclude" && matchesPattern(methodName, rule.pattern, rule.matchType)) {
            Windbg.log(`Filter: Method '${methodName}' (in module '${moduleName}') excluded by rule: ${JSON.stringify(rule)}`);
            return false; // 方法被排除
        }
    }
    
    // 2. 检查包含规则
    const methodIncludeRules = methodRules.filter(r => r.type === "include");
    if (methodIncludeRules.length > 0) {
        let matchedMethodInclude = false;
        for (const rule of methodIncludeRules) {
            if (matchesPattern(methodName, rule.pattern, rule.matchType)) {
                matchedMethodInclude = true;
                break;
            }
        }
        if (!matchedMethodInclude) {
            Windbg.log(`Filter: Method '${methodName}' (in module '${moduleName}') not included by any method 'include' rule.`);
            return false; // 方法未被任何包含规则匹配
        }
    }

    // 如果所有检查都通过了
    Windbg.log(`Filter: Processing '${moduleName}'-'${methodName}' as it passed all filter rules.`);
    return true;
}

function extractFuncInfo(filterRules){
    //extract ILCode, Method and Module info
    var ptr =  Windbg.getRegVal('esp') + 0xC;
    var method_info_addr = Windbg.getUint32(ptr);
	var arr = Windbg.getBytesArr(method_info_addr,24);
    var method_info = new MethodInfo(ArrToDatView(arr));

    try{
        var lines = Windbg.system("!dumpmd " + method_info.method_handle.toString(16));   
        var md_token = lines[3].split(": ")[1].trim();
        var method_name = lines[0].split(": ")[1].trim();
        lines = Windbg.system("!dumpmodule " + method_info.module_handle.toString(16));
        var module_name =lines[0].split(": ")[1].trim();
    } catch(e){
        Windbg.log(lines[0] + ", skip.");
        return;
    }

    if (!applyFilterRules(module_name, method_name, filterRules)) {
        Windbg.log(`Skipping method ${module_name} - ${method_name} due to filter rules.`); // applyFilterRules会打印日志
        return; // 不符合规则，跳过此方法
    }

    var il_codes = Windbg.getBytesArr(method_info.ilcode_addr, method_info.ilcode_size);

    //extract LocalsSig info 
    Windbg.system("bp 0x0304648e") // at clrjit!Compiler::lvaInitTypeRef, after 'localsSig = info.compCompHnd->getArgNext(localsSig)'
    Windbg.system("g")
    var localSig = [];
    var v1 = Windbg.getRegVal('ebx');
    var v13 = Windbg.getUint32(v1+0x1958);
    var startAddr = Windbg.getUint32(v13+0x78);
    if(startAddr != 0){
        var endAddr = Windbg.getRegVal('eax');
        var size = endAddr-startAddr;
        localSig = Windbg.getBytesArr(startAddr,size);
    }

    //extract EH info
    var clauses = []
    Windbg.system("bp 0x03051e3d") //at clrjit!Compiler::fgFindBasicBlocks, after 'info.compCompHnd->getEHinfo(info.compMethodHnd, XTnum, &clause)'
    for(var i = 0; i < method_info.eh_count; i++){
        Windbg.system("g")
        var ptr = Windbg.getRegVal('esp') + 0x7C;
        var arr = Windbg.getBytesArr(ptr,0x1C);
        var clauseInfo = new EHClauseInfo(ArrToDatView(arr));
        clauses.push({ HandlerType: clauseInfo.HandlerType,
          TryStartOffset: clauseInfo.TryOffset,
          TryEndOffset: clauseInfo.TryOffset+clauseInfo.TryLength,
          HandlerStartOffset: clauseInfo.HandlerOffset,
          HandlerEndOffset: clauseInfo.HandlerOffset+clauseInfo.HandlerLength,
          CatchTypeTokenOrFilterOffset: clauseInfo.CatchTypeTokenOrFilterOffset})
    }

    // save json file
    let moduleEntry = modulesInfo.find(m => m.ModuleName === module_name);

    if (!moduleEntry) {
        // If module doesn't exist, create a new entry
        moduleEntry = {
            ModuleName: module_name,
            MethodsInfo: []
        };
        modulesInfo.push(moduleEntry);
    }

    // Create the method information object
    const methodData = {
        MethodName: method_name,
        MethodToken: parseInt(md_token, 16),
        ILBytes: ArrayToHexStr(il_codes),
        MaxStack: method_info.max_stack,
        LocalsSignatureBytes: ArrayToHexStr(localSig),
        ExceptionHandlers: clauses // clauses is already an array of objects
    };

    // Add the method info to the module's MethodsInfo array
    moduleEntry.MethodsInfo.push(methodData);

}

var modulesInfo = []

function invokeScript()
{
    const filterRules = [
        {target:FilterTargets.MODULE, type:FilterTypes.INCLUDE, matchType:FilterMatchTypes.CONTAINS, pattern:"FileCrypto.exe"},
        {target:FilterTargets.METHOD, type:FilterTypes.INCLUDE, matchType:FilterMatchTypes.CONTAINS, pattern:"Process()"},
    ]; 
    
    Windbg.log('Start...');
    
    Windbg.system("!tt 100");
    const startTime = Date.now();
    var jitMethodCount = parseInt(Windbg.system(`dx -r2 @$cursession.TTD.Calls("clrjit!CILJit::compileMethod").Count()`)[0].split(": ")[1].trim(),16); 
    Windbg.log(`Total JIT compilations to process: ${jitMethodCount}`);
    for (var index = 0; index < jitMethodCount; index++) {
        const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2);
        Windbg.log(`Progress: ${index}/${jitMethodCount} ${((index / jitMethodCount) * 100).toFixed(2)}%, Elapsed Time: ${elapsedTime}s`);
        Windbg.system(`dx -r2 @$cursession.TTD.Calls("clrjit!CILJit::compileMethod")[0x${index.toString(16)}].@"TimeStart".SeekTo()`)
        try {
            extractFuncInfo(filterRules);
        } catch (e) {
            Windbg.log(`Error processing index ${index}: ${e.message}`);
            Windbg.log(`Stack: ${e.stack}`);
        }
    }
    Windbg.log("Using filter rules: " + JSON.stringify(filterRules, null, 2));

    WriteToFile("D:\\FileCrypto.json", JSON.stringify({"ModulesInfo":modulesInfo}, null, 2)); 
    Windbg.log('Finished extracting JIT information.');
}