// Decompile every non-external function of the current program into one C file.
// Headless usage:
//   analyzeHeadless /tmp/proj p -import <binary> \
//     -scriptPath /ctf/ghidra_scripts -postScript DecompileAll.java <out.c> -deleteProject
// Without an argument the output goes to ./<program name>.decompiled.c
//@category CTF

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileAll extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args.length > 0 ? args[0] : currentProgram.getName() + ".decompiled.c");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int ok = 0, failed = 0;
        try (PrintWriter writer = new PrintWriter(out, "UTF-8")) {
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (function.isExternal() || function.isThunk()) {
                    continue;
                }
                writer.printf("// %s @ %s%n", function.getName(), function.getEntryPoint());
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result.decompileCompleted()) {
                    writer.println(result.getDecompiledFunction().getC());
                    ok++;
                } else {
                    writer.printf("// decompile failed: %s%n%n", result.getErrorMessage());
                    failed++;
                }
            }
        } finally {
            decompiler.dispose();
        }
        println(String.format("DecompileAll: %d functions, %d failed -> %s", ok, failed, out.getAbsolutePath()));
    }
}
