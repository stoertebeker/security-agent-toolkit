// Focused reference-driven decompilation for selected firmware binaries.
// @category SecurityAgentToolkit

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
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
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class SatDecompileRefs extends GhidraScript {
    private static final int MAX_C_CHARS = 30000;
    private static final int XREF_CONTEXT_BEFORE = 4;
    private static final int XREF_CONTEXT_AFTER = 6;
    private static final int MAX_XREF_CONTEXTS_PER_FUNCTION = 12;

    private static class DirectRef {
        final String needle;
        final Address fromAddress;
        final String target;

        DirectRef(String needle, Address fromAddress, String target) {
            this.needle = needle;
            this.fromAddress = fromAddress;
            this.target = target;
        }

        String key() {
            return needle + "@" + fromAddress + "->" + target;
        }
    }

    private static class Candidate {
        final LinkedHashSet<String> reasons = new LinkedHashSet<>();
        final Set<String> directNeedles = new HashSet<>();
        final LinkedHashMap<String, DirectRef> directRefs = new LinkedHashMap<>();
        int score = 0;
        boolean direct = false;
    }

    private static boolean containsIgnoreCase(String haystack, String needle) {
        return haystack != null && needle != null &&
            haystack.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    private static int directScore(String needle) {
        int lengthBonus = Math.min(40, needle.length() * 2);
        int syntaxBonus = (needle.contains(".") || needle.contains("_") || needle.contains("/")) ? 30 : 0;
        return 100 + lengthBonus + syntaxBonus;
    }

    private static void addReason(
        Map<Function, Candidate> selected,
        Function function,
        String reason,
        int score,
        String needle,
        boolean direct,
        Address fromAddress,
        String target
    ) {
        if (function == null) {
            return;
        }
        Candidate candidate = selected.computeIfAbsent(function, key -> new Candidate());
        if (candidate.reasons.add(reason)) {
            candidate.score += score;
        }
        if (direct) {
            candidate.direct = true;
            if (needle != null) {
                candidate.directNeedles.add(needle);
            }
            if (needle != null && fromAddress != null) {
                DirectRef directRef = new DirectRef(needle, fromAddress, target == null ? "" : target);
                candidate.directRefs.putIfAbsent(directRef.key(), directRef);
            }
        }
    }

    private void addReferencesToAddress(
        Map<Function, Candidate> selected,
        ReferenceManager references,
        Address address,
        FunctionManager functions,
        String needle,
        String reason
    ) {
        ReferenceIterator iterator = references.getReferencesTo(address);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Reference reference = iterator.next();
            Function caller = functions.getFunctionContaining(reference.getFromAddress());
            addReason(
                selected, caller, reason + " via " + reference.getFromAddress(),
                directScore(needle), needle, true,
                reference.getFromAddress(), address.toString()
            );
        }
    }

    private static String instructionText(Instruction instruction) {
        if (instruction == null) {
            return "";
        }
        return instruction.getAddress() + "  " + instruction.toString();
    }

    private void writeXrefContext(PrintWriter writer, Listing listing, DirectRef directRef) {
        writer.println("### xref '" + directRef.needle + "' @ " + directRef.fromAddress +
            (directRef.target.isBlank() ? "" : " -> " + directRef.target));
        List<Instruction> before = new ArrayList<>();
        Instruction current = listing.getInstructionAt(directRef.fromAddress);
        if (current == null) {
            current = listing.getInstructionContaining(directRef.fromAddress);
        }
        Instruction cursor = current;
        for (int i = 0; i < XREF_CONTEXT_BEFORE && cursor != null; i++) {
            cursor = listing.getInstructionBefore(cursor.getAddress());
            if (cursor != null) {
                before.add(0, cursor);
            }
        }
        for (Instruction instruction : before) {
            writer.println("  " + instructionText(instruction));
        }
        if (current != null) {
            writer.println("> " + instructionText(current));
            cursor = current;
            for (int i = 0; i < XREF_CONTEXT_AFTER; i++) {
                cursor = listing.getInstructionAfter(cursor.getAddress());
                if (cursor == null) {
                    break;
                }
                writer.println("  " + instructionText(cursor));
            }
        }
        else {
            writer.println("  (no decoded instruction at reference address)");
        }
        writer.println();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) {
            throw new IllegalArgumentException(
                "Usage: SatDecompileRefs.java <output-file> <max-functions> <decompile-timeout-seconds> <needle> [needle ...]"
            );
        }

        File output = new File(args[0]);
        int maxFunctions = Integer.parseInt(args[1]);
        int decompileTimeout = Integer.parseInt(args[2]);
        List<String> needles = new ArrayList<>();
        for (int i = 3; i < args.length; i++) {
            if (!args[i].isBlank()) {
                needles.add(args[i]);
            }
        }
        if (needles.isEmpty()) {
            throw new IllegalArgumentException("At least one non-empty needle is required");
        }
        if (decompileTimeout < 1) {
            throw new IllegalArgumentException("Decompiler timeout must be positive");
        }

        Listing listing = currentProgram.getListing();
        FunctionManager functions = currentProgram.getFunctionManager();
        ReferenceManager references = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Map<Function, Candidate> selected = new LinkedHashMap<>();

        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();
            String representation = data.getDefaultValueRepresentation();
            for (String needle : needles) {
                if (containsIgnoreCase(representation, needle)) {
                    addReferencesToAddress(
                        selected, references, data.getAddress(), functions, needle,
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

                // When a needle directly names a recovered/generated function
                // symbol (for example FUN_0001c108), include the function itself.
                // This makes a first-pass caller visible as a precise second-pass
                // target without needing a separate Ghidra project or script.
                Function namedFunction = functions.getFunctionAt(symbol.getAddress());
                if (namedFunction != null) {
                    addReason(
                        selected, namedFunction,
                        "direct function-symbol match '" + needle + "' -> " + name,
                        directScore(needle) + 80, needle, true, null, symbol.getAddress().toString()
                    );
                }

                Reference[] symbolReferences = symbol.getReferences(null);
                for (Reference reference : symbolReferences) {
                    Function caller = functions.getFunctionContaining(reference.getFromAddress());
                    addReason(
                        selected, caller,
                        "symbol match '" + needle + "' -> " + name + " via " + reference.getFromAddress(),
                        directScore(needle), needle, true,
                        reference.getFromAddress(), symbol.getAddress().toString()
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
                    "direct caller of " + callee.getName() + " @ " + callee.getEntryPoint(),
                    15, null, false, null, null
                );
            }
        }

        List<Map.Entry<Function, Candidate>> ordered = new ArrayList<>(selected.entrySet());
        ordered.sort(
            Comparator
                .<Map.Entry<Function, Candidate>>comparingInt(entry -> entry.getValue().directNeedles.size()).reversed()
                .thenComparing(Comparator.comparingInt((Map.Entry<Function, Candidate> entry) -> entry.getValue().score).reversed())
                .thenComparing(entry -> entry.getKey().getEntryPoint())
        );

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
            writer.println("decompile timeout per function: " + decompileTimeout + " seconds");
            writer.println();

            int emitted = 0;
            for (Map.Entry<Function, Candidate> entry : ordered) {
                if (monitor.isCancelled() || emitted >= maxFunctions) {
                    break;
                }
                Function function = entry.getKey();
                Candidate candidate = entry.getValue();
                writer.println("## " + function.getName() + " @ " + function.getEntryPoint());
                writer.println("priority score: " + candidate.score);
                writer.println("direct needles: " + (candidate.directNeedles.isEmpty() ? "(caller-context only)" : String.join(", ", candidate.directNeedles)));
                writer.println("reasons:");
                for (String reason : candidate.reasons) {
                    writer.println("- " + reason);
                }
                if (!candidate.directRefs.isEmpty()) {
                    writer.println();
                    writer.println("xref instruction contexts:");
                    int shown = 0;
                    for (DirectRef directRef : candidate.directRefs.values()) {
                        if (shown >= MAX_XREF_CONTEXTS_PER_FUNCTION) {
                            writer.println("(additional xref contexts omitted)");
                            break;
                        }
                        writeXrefContext(writer, listing, directRef);
                        shown++;
                    }
                }

                DecompileResults results = decompiler.decompileFunction(function, decompileTimeout, monitor);
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
