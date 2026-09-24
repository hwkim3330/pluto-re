import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
// Decompile functions after stripping their committed local variables (works around
// "Forced merge caused intersection"). Run on a scratch copy of the project.
public class DecompileStripped extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    PrintWriter w = new PrintWriter(new FileWriter(a[0]));
    DecompInterface d = new DecompInterface();
    DecompileOptions o = new DecompileOptions();
    o.setMaxPayloadMBytes(512); o.setMaxInstructions(400000);
    d.setOptions(o);
    d.openProgram(currentProgram);
    for (int i = 1; i < a.length; i++) {
      Function f = getFunctionAt(toAddr(a[i]));
      for (Variable v : f.getLocalVariables()) f.removeVariable(v);
      DecompileResults r = d.decompileFunction(f, 1200, monitor);
      w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint());
      if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
      else w.println("// failed: " + (r == null ? "null" : r.getErrorMessage()));
    }
    w.close();
  }
}
