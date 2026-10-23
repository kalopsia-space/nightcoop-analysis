// Decompile every function in the current program to <out>/all.c
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DumpAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        int n = 0, fail = 0;
        try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                w.println("//==== " + f.getEntryPoint() + " " + f.getName(true));
                DecompileResults r = d.decompileFunction(f, 60, monitor);
                if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
                else { w.println("// DECOMPILE FAILED: " + (r == null ? "null" : r.getErrorMessage())); fail++; }
                if (++n % 1000 == 0) println("decompiled " + n);
            }
        }
        println("DONE total=" + n + " failed=" + fail);
    }
}
