import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DecompileAll extends GhidraScript {
  public void run() throws Exception {
    String out = getScriptArgs()[0];
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    PrintWriter w = new PrintWriter(new FileWriter(out));
    int n=0, fail=0;
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      if (f.isThunk() || f.isExternal()) continue;
      DecompileResults r = d.decompileFunction(f, 120, monitor);
      w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
      if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC()); else { w.println("// decompile failed"); fail++; }
      n++;
    }
    w.close(); println("functions=" + n + " failed=" + fail);
  }
}
