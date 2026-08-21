// Focused reference-driven decompilation for selected firmware binaries.
// @category SecurityAgentToolkit

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class SatDecompileRefs extends GhidraScript {
    private static final int MAX_C_CHARS = 30000;

    private static boolean containsIgnoreCase(String haystack, String needle) {
        return haystack != null && needle != null &&
            haystack.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    private static void addReason(
        Map<Function, LinkedHashSet<String>> selected,
        Function function,
        String reason
    ) {
        if (function == null) {
            return;
        }
        selected.computeIfAbsent(function, key -> new LinkedHashSet<>()).add(reason);
    }

    private void addReferencesToAddress(
        Map<Function, LinkedHashSet<String>> selected,
        ReferenceManager references,
        ghidra.program.model.address.Address address,
        FunctionManager functions,
        String reason
    ) {
        ReferenceIterator iterator = references.getReferencesTo(address);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Reference reference = iterator.next();
            Function caller = functions.getFunctionContaining(reference.getFromAddress());
            addReason(selected, caller, reason + " via " + reference.getFromAddress());
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException(
                "Usage: SatDecompileRefs.java <output-file> <max-functions> <needle> [needle ...]"
            );
        }

        File output = new File(args[0]);
        int maxFunctions = Integer.parseInt(args[1]);
        List<String> needles = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            if (!args[i].isBlank()) {
                needles.add(args[i]);
            }
        }
        if (needles.isEmpty()) {
            throw new IllegalArgumentException("At least one non-empty needle is required");
        }

        Listing listing = currentProgram.getListing();
        FunctionManager functions = currentProgram.getFunctionManager();
        ReferenceManager references = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Map<Function, LinkedHashSet<String>> selected = new LinkedHashMap<>();

        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();
            String representation = data.getDefaultValueRepresentation();
            for (String needle : needles) {
                if (containsIgnoreCase(representation, needle)) {
                    addReferencesToAddress(
                        selected, references, data.getAddress(), functions,
                        "string/data match '" + needle + "' @ " + data.getAddress()
                    );
                }
            }
        }

        SymbolIterator symbolIterator = symbols.getAllSymbols(true);
        while (symbolIterator.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbolIterator.next();
            String name = symbol.getName();
            for (String needle : needles) {
                if (!containsIgnoreCase(name, needle)) {
                    continue;
                }
                Reference[] symbolReferences = symbol.getReferences(null);
                for (Reference reference : symbolReferences) {
                    Function caller = functions.getFunctionContaining(reference.getFromAddress());
                    addReason(
                        selected, caller,
                        "symbol match '" + needle + "' -> " + name + " via " + reference.getFromAddress()
                    );
                }
            }
        }

        // One caller layer gives useful control-flow context without exploding scope.
        List<Function> seedFunctions = new ArrayList<>(selected.keySet());
        for (Function callee : seedFunctions) {
            ReferenceIterator callerRefs = references.getReferencesTo(callee.getEntryPoint());
            while (callerRefs.hasNext() && !monitor.isCancelled()) {
                Reference reference = callerRefs.next();
                Function caller = functions.getFunctionContaining(reference.getFromAddress());
                addReason(
                    selected, caller,
                    "direct caller of " + callee.getName() + " @ " + callee.getEntryPoint()
                );
            }
        }

        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Decompiler initialization failed: " + decompiler.getLastMessage());
        }

        try (PrintWriter writer = new PrintWriter(
            new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8)
        )) {
            writer.println("# SAT focused Ghidra decompilation slice");
            writer.println("program: " + currentProgram.getName());
            writer.println("language: " + currentProgram.getLanguageID());
            writer.println("compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
            writer.println("needles: " + String.join(", ", needles));
            writer.println("matched functions before limit: " + selected.size());
            writer.println();

            int emitted = 0;
            for (Map.Entry<Function, LinkedHashSet<String>> entry : selected.entrySet()) {
                if (monitor.isCancelled() || emitted >= maxFunctions) {
                    break;
                }
                Function function = entry.getKey();
                writer.println("## " + function.getName() + " @ " + function.getEntryPoint());
                writer.println("reasons:");
                for (String reason : entry.getValue()) {
                    writer.println("- " + reason);
                }

                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
                    writer.println("decompile: FAILED");
                    writer.println("error: " + results.getErrorMessage());
                    writer.println();
                    emitted++;
                    continue;
                }

                String code = results.getDecompiledFunction().getC();
                if (code.length() > MAX_C_CHARS) {
                    code = code.substring(0, MAX_C_CHARS) + "\n/* truncated by SAT */\n";
                }
                writer.println("```c");
                writer.print(code);
                if (!code.endsWith("\n")) {
                    writer.println();
                }
                writer.println("```");
                writer.println();
                emitted++;
            }
            writer.println("emitted functions: " + emitted);
        }
        finally {
            decompiler.dispose();
        }

        println("SAT focused decompilation written to " + output.getAbsolutePath());
    }
}
