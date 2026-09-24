import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DecompileOne extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    String out = a[0];
    DecompInterface d = new DecompInterface();
    DecompileOptions o = new DecompileOptions();
    o.setMaxPayloadMBytes(512); o.setMaxInstructions(200000);
    d.setOptions(o);
    d.openProgram(currentProgram);
    PrintWriter w = new PrintWriter(new FileWriter(out));
    for (int i = 1; i < a.length; i++) {
      Function f = getFunctionAt(toAddr(a[i]));
      DecompileResults r = d.decompileFunction(f, 1200, monitor);
      w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint());
      if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
      else w.println("// failed: " + (r == null ? "null" : r.getErrorMessage()));
    }
    w.close();
  }
}
