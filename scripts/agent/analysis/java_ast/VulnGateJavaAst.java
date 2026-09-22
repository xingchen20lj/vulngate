/*
 * Bounded Java syntax fact dumper for VulnGate.
 *
 * This program uses only JavacTask.parse().  It never calls analyze(),
 * generate(), annotation processors, class loading, or target code.  The
 * Python adapter supplies source through stdin and retains the source revision
 * and resource budgets, so this helper neither walks the target tree nor
 * emits source text.
 */

import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.BlockTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.CompoundAssignmentTree;
import com.sun.source.tree.ConditionalExpressionTree;
import com.sun.source.tree.DoWhileLoopTree;
import com.sun.source.tree.EnhancedForLoopTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.ForLoopTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.IfTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.StatementTree;
import com.sun.source.tree.SwitchExpressionTree;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.ThrowTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TryTree;
import com.sun.source.tree.UnaryTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.tree.WhileLoopTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

public final class VulnGateJavaAst {
    private static final PrintWriter OUT = new PrintWriter(
        new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
    private static final int TOKEN_LIMIT = 16;

    private VulnGateJavaAst() {
    }

    private static final class SourceUnit extends SimpleJavaFileObject {
        private final String source;

        SourceUnit(String source) {
            super(URI.create("mem:///VulnGateInput.java"), Kind.SOURCE);
            this.source = source;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
        }
    }

    private static final class LimitExceeded extends RuntimeException {
        final String status;

        LimitExceeded(String status) {
            this.status = status;
        }
    }

    private static void row(String... fields) {
        StringBuilder line = new StringBuilder();
        for (int index = 0; index < fields.length; index++) {
            if (index > 0) {
                line.append('\t');
            }
            line.append(java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(String.valueOf(fields[index]).getBytes(StandardCharsets.UTF_8)));
        }
        OUT.println(line);
    }

    private static String readInput() throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = System.in.read(chunk)) >= 0) {
            buffer.write(chunk, 0, read);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '\\': result.append("\\\\"); break;
                case '\"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        result.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        result.append(ch);
                    }
            }
        }
        return result.append('\"').toString();
    }

    @SuppressWarnings("unchecked")
    private static String json(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return quote((String) value);
        }
        if (value instanceof Boolean || value instanceof Number) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?>) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> item : ((Map<?, ?>) value).entrySet()) {
                sorted.put(String.valueOf(item.getKey()), item.getValue());
            }
            StringBuilder result = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> item : sorted.entrySet()) {
                if (!first) {
                    result.append(',');
                }
                result.append(quote(item.getKey())).append(':').append(json(item.getValue()));
                first = false;
            }
            return result.append('}').toString();
        }
        if (value instanceof Collection<?>) {
            StringBuilder result = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Collection<?>) value) {
                if (!first) {
                    result.append(',');
                }
                result.append(json(item));
                first = false;
            }
            return result.append(']').toString();
        }
        return quote(String.valueOf(value));
    }

    private static List<String> identifiers(Tree tree) {
        if (tree == null) {
            return Collections.emptyList();
        }
        Set<String> values = new LinkedHashSet<>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitIdentifier(IdentifierTree node, Void ignored) {
                String name = String.valueOf(node.getName());
                if (!name.isEmpty() && !"this".equals(name) && !"super".equals(name)) {
                    values.add(name);
                }
                return super.visitIdentifier(node, ignored);
            }
        }.scan(tree, null);
        List<String> result = new ArrayList<>(values);
        result.sort(String::compareTo);
        return result.subList(0, Math.min(TOKEN_LIMIT, result.size()));
    }

    private static String leafName(ExpressionTree tree) {
        if (tree instanceof IdentifierTree) {
            return String.valueOf(((IdentifierTree) tree).getName());
        }
        if (tree instanceof MemberSelectTree) {
            return String.valueOf(((MemberSelectTree) tree).getIdentifier());
        }
        return "";
    }

    private static String callName(ExpressionTree tree) {
        if (tree instanceof IdentifierTree) {
            return String.valueOf(((IdentifierTree) tree).getName());
        }
        if (tree instanceof MemberSelectTree) {
            MemberSelectTree select = (MemberSelectTree) tree;
            String owner = callName(select.getExpression());
            String leaf = String.valueOf(select.getIdentifier());
            return owner.isEmpty() ? leaf : owner + "." + leaf;
        }
        return "";
    }

    private static String lastIdentifier(Tree tree) {
        if (tree == null) {
            return "";
        }
        List<String> values = new ArrayList<>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitIdentifier(IdentifierTree node, Void ignored) {
                values.add(String.valueOf(node.getName()));
                return super.visitIdentifier(node, ignored);
            }
        }.scan(tree, null);
        return values.isEmpty() ? "" : values.get(values.size() - 1);
    }

    private static boolean negative(ExpressionTree test) {
        while (test instanceof ParenthesizedTree) {
            test = ((ParenthesizedTree) test).getExpression();
        }
        if (test instanceof UnaryTree) {
            return ((UnaryTree) test).getKind() == Tree.Kind.LOGICAL_COMPLEMENT;
        }
        if (test instanceof BinaryTree) {
            Tree.Kind kind = ((BinaryTree) test).getKind();
            return kind == Tree.Kind.NOT_EQUAL_TO;
        }
        return false;
    }

    private static String terminal(StatementTree statement) {
        if (statement == null) {
            return "none";
        }
        if (statement instanceof BlockTree) {
            List<? extends StatementTree> statements = ((BlockTree) statement).getStatements();
            return statements.isEmpty() ? "none" : terminal(statements.get(0));
        }
        if (statement instanceof ReturnTree) {
            return "return";
        }
        if (statement instanceof ThrowTree) {
            return "throw";
        }
        return "none";
    }

    private static final class Scanner extends TreePathScanner<Void, Void> {
        private final CompilationUnitTree unit;
        private final SourcePositions positions;
        private final String packageName;
        private final int maxNodes;
        private final int maxDepth;
        private final List<String> classes = new ArrayList<>();
        private final List<String> methods = new ArrayList<>();
        private int nodes = 0;
        private int depth = 0;

        Scanner(CompilationUnitTree unit, SourcePositions positions,
                int maxNodes, int maxDepth) {
            this.unit = unit;
            this.positions = positions;
            this.maxNodes = Math.max(1, maxNodes);
            this.maxDepth = Math.max(1, maxDepth);
            this.packageName = unit.getPackageName() == null ? ""
                : String.valueOf(unit.getPackageName());
        }

        int nodeCount() {
            return nodes;
        }

        @Override
        public Void scan(Tree tree, Void ignored) {
            if (tree == null) {
                return null;
            }
            nodes++;
            if (nodes > maxNodes) {
                throw new LimitExceeded("node-limit");
            }
            depth++;
            try {
                if (depth > maxDepth) {
                    throw new LimitExceeded("depth-limit");
                }
                return super.scan(tree, ignored);
            } finally {
                depth--;
            }
        }

        private Map<String, Object> attrs(Object... values) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (int index = 0; index + 1 < values.length; index += 2) {
                result.put(String.valueOf(values[index]), values[index + 1]);
            }
            return result;
        }

        private Map<String, Integer> span(Tree tree) {
            Map<String, Integer> result = new LinkedHashMap<>();
            if (tree == null) {
                return result;
            }
            long start = positions.getStartPosition(unit, tree);
            long end = positions.getEndPosition(unit, tree);
            if (start < 0) {
                return result;
            }
            int startLine = (int) unit.getLineMap().getLineNumber(start);
            int endLine = (int) unit.getLineMap().getLineNumber(
                Math.max(start, end > start ? end - 1 : start));
            result.put("start", startLine);
            result.put("end", Math.max(startLine, endLine));
            return result;
        }

        private void emit(String kind, Tree tree, String name,
                          Map<String, Object> attributes) {
            long start = tree == null ? -1 : positions.getStartPosition(unit, tree);
            long end = tree == null ? -1 : positions.getEndPosition(unit, tree);
            int line = start < 0 ? 0 : (int) unit.getLineMap().getLineNumber(start);
            int endLine = start < 0 ? line : (int) unit.getLineMap().getLineNumber(
                Math.max(start, end > start ? end - 1 : start));
            int column = start < 0 ? 0 : Math.max(0,
                (int) unit.getLineMap().getColumnNumber(start) - 1);
            int endColumn = end < 0 ? column : Math.max(column,
                (int) unit.getLineMap().getColumnNumber(Math.max(start, end)) - 1);
            row("F", kind, Integer.toString(line), Integer.toString(Math.max(line, endLine)),
                Integer.toString(column), Integer.toString(endColumn), scope(), name,
                json(attributes));
        }

        private String qualifiedClass() {
            List<String> parts = new ArrayList<>();
            if (!packageName.isEmpty()) {
                parts.add(packageName);
            }
            parts.addAll(classes);
            return String.join(".", parts);
        }

        private String scope() {
            List<String> parts = new ArrayList<>();
            if (!packageName.isEmpty()) {
                parts.add(packageName);
            }
            parts.addAll(classes);
            parts.addAll(methods);
            return String.join(".", parts);
        }

        @Override
        public Void visitClass(ClassTree node, Void ignored) {
            String name = String.valueOf(node.getSimpleName());
            if (name.isEmpty()) {
                name = "<anonymous@" + span(node).getOrDefault("start", 0) + ">";
            }
            String parentClass = String.join(".", classes);
            String qualified = qualifiedClass();
            if (!qualified.isEmpty()) {
                qualified += ".";
            }
            qualified += name;
            emit("symbol", node, name, attrs(
                "symbol_kind", node.getKind().name().toLowerCase(Locale.ROOT),
                "qualified_name", qualified,
                "namespace", packageName,
                "class_name", parentClass,
                "parameters", Collections.emptyList()));
            classes.add(name);
            try {
                return super.visitClass(node, ignored);
            } finally {
                classes.remove(classes.size() - 1);
            }
        }

        @Override
        public Void visitMethod(MethodTree node, Void ignored) {
            String rawName = String.valueOf(node.getName());
            boolean constructor = "<init>".equals(rawName);
            String name = constructor ? "<init>" : rawName;
            String owner = qualifiedClass();
            String qualified = owner.isEmpty() ? name : owner + "#" + name;
            List<String> parameters = new ArrayList<>();
            List<String> parameterTypes = new ArrayList<>();
            for (VariableTree parameter : node.getParameters()) {
                parameters.add(String.valueOf(parameter.getName()));
                parameterTypes.add(parameter.getType() == null ? "" :
                    String.valueOf(parameter.getType()));
            }
            emit("symbol", node, name, attrs(
                "symbol_kind", constructor ? "constructor" : "method",
                "qualified_name", qualified,
                "namespace", packageName,
                "class_name", String.join(".", classes),
                "parameters", parameters,
                "parameter_types", parameterTypes,
                "signature", name + "(" + String.join(",", parameterTypes) + ")"));
            methods.add(name);
            try {
                int position = 0;
                for (VariableTree parameter : node.getParameters()) {
                    emit("parameter", parameter, String.valueOf(parameter.getName()), attrs(
                        "position", position++,
                        "parameter_kind", "positional-or-keyword",
                        "symbol_qualified_name", qualified));
                }
                return super.visitMethod(node, ignored);
            } finally {
                methods.remove(methods.size() - 1);
            }
        }

        @Override
        public Void visitVariable(VariableTree node, Void ignored) {
            if (node.getInitializer() != null) {
                emit("assignment", node, String.valueOf(node.getName()), attrs(
                    "assignment_kind", "VariableTree",
                    "target_tokens", Collections.singletonList(String.valueOf(node.getName())),
                    "value_tokens", identifiers(node.getInitializer())));
            }
            return super.visitVariable(node, ignored);
        }

        @Override
        public Void visitAssignment(AssignmentTree node, Void ignored) {
            emit("assignment", node, "", attrs(
                "assignment_kind", "AssignmentTree",
                "target_tokens", identifiers(node.getVariable()),
                "value_tokens", identifiers(node.getExpression())));
            return super.visitAssignment(node, ignored);
        }

        @Override
        public Void visitCompoundAssignment(CompoundAssignmentTree node, Void ignored) {
            emit("assignment", node, "", attrs(
                "assignment_kind", "CompoundAssignmentTree",
                "target_tokens", identifiers(node.getVariable()),
                "value_tokens", identifiers(node.getExpression())));
            return super.visitCompoundAssignment(node, ignored);
        }

        @Override
        public Void visitReturn(ReturnTree node, Void ignored) {
            emit("return", node, "", attrs("value_tokens", identifiers(node.getExpression())));
            return super.visitReturn(node, ignored);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void ignored) {
            List<List<String>> arguments = new ArrayList<>();
            List<String> kinds = new ArrayList<>();
            for (ExpressionTree argument : node.getArguments()) {
                arguments.add(identifiers(argument));
                kinds.add(argument instanceof LiteralTree ? "literal" : "expression");
            }
            Tree parent = getCurrentPath().getParentPath() == null ? null
                : getCurrentPath().getParentPath().getLeaf();
            String context = "direct";
            List<String> targets = Collections.emptyList();
            if (parent instanceof ReturnTree) {
                context = "returned";
            } else if (parent instanceof AssignmentTree) {
                context = "assigned";
                targets = identifiers(((AssignmentTree) parent).getVariable());
            } else if (parent instanceof VariableTree) {
                context = "assigned";
                targets = Collections.singletonList(String.valueOf(((VariableTree) parent).getName()));
            } else if (parent instanceof MethodInvocationTree) {
                context = "argument";
            }
            emit("call", node, callName(node.getMethodSelect()), attrs(
                "leaf_name", leafName(node.getMethodSelect()),
                "dispatch", "unresolved",
                "callee_kind", node.getMethodSelect().getKind().name(),
                "argument_tokens", arguments,
                "argument_kinds", kinds,
                "use_context", context,
                "target_tokens", targets));
            return super.visitMethodInvocation(node, ignored);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void ignored) {
            List<List<String>> arguments = new ArrayList<>();
            List<String> kinds = new ArrayList<>();
            for (ExpressionTree argument : node.getArguments()) {
                arguments.add(identifiers(argument));
                kinds.add(argument instanceof LiteralTree ? "literal" : "expression");
            }
            Tree parent = getCurrentPath().getParentPath() == null ? null
                : getCurrentPath().getParentPath().getLeaf();
            String context = "direct";
            List<String> targets = Collections.emptyList();
            if (parent instanceof ReturnTree) {
                context = "returned";
            } else if (parent instanceof AssignmentTree) {
                context = "assigned";
                targets = identifiers(((AssignmentTree) parent).getVariable());
            } else if (parent instanceof VariableTree) {
                context = "assigned";
                targets = Collections.singletonList(String.valueOf(((VariableTree) parent).getName()));
            }
            String constructor = lastIdentifier(node.getIdentifier());
            emit("call", node, constructor, attrs(
                "leaf_name", constructor,
                "dispatch", "unresolved",
                "callee_kind", "NEW_CLASS",
                "constructor", true,
                "argument_tokens", arguments,
                "argument_kinds", kinds,
                "use_context", context,
                "target_tokens", targets));
            return super.visitNewClass(node, ignored);
        }

        private void branch(Tree node, String kind, ExpressionTree test,
                            StatementTree body, StatementTree alternate) {
            emit("branch", node, "", attrs(
                "branch_kind", kind,
                "condition_tokens", identifiers(test),
                "test_span", span(test),
                "body_span", span(body),
                "alternate_span", span(alternate),
                "terminal", terminal(body),
                "negative_test", negative(test)));
        }

        @Override
        public Void visitIf(IfTree node, Void ignored) {
            branch(node, "if", node.getCondition(), node.getThenStatement(), node.getElseStatement());
            return super.visitIf(node, ignored);
        }

        @Override
        public Void visitWhileLoop(WhileLoopTree node, Void ignored) {
            branch(node, "while", node.getCondition(), node.getStatement(), null);
            return super.visitWhileLoop(node, ignored);
        }

        @Override
        public Void visitDoWhileLoop(DoWhileLoopTree node, Void ignored) {
            branch(node, "do-while", node.getCondition(), node.getStatement(), null);
            return super.visitDoWhileLoop(node, ignored);
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void ignored) {
            branch(node, "for", node.getCondition(), node.getStatement(), null);
            return super.visitForLoop(node, ignored);
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void ignored) {
            branch(node, "enhanced-for", node.getExpression(), node.getStatement(), null);
            return super.visitEnhancedForLoop(node, ignored);
        }

        @Override
        public Void visitTry(TryTree node, Void ignored) {
            emit("branch", node, "", attrs(
                "branch_kind", "try",
                "condition_tokens", Collections.emptyList(),
                "test_span", span(node),
                "body_span", span(node.getBlock()),
                "alternate_span", span(node.getFinallyBlock()),
                "terminal", terminal(node.getBlock()),
                "negative_test", false));
            return super.visitTry(node, ignored);
        }

        @Override
        public Void visitSwitch(SwitchTree node, Void ignored) {
            emit("branch", node, "", attrs(
                "branch_kind", "switch",
                "condition_tokens", identifiers(node.getExpression()),
                "test_span", span(node.getExpression()),
                "body_span", span(node),
                "alternate_span", Collections.emptyMap(),
                "terminal", "none",
                "negative_test", false));
            return super.visitSwitch(node, ignored);
        }

        @Override
        public Void visitSwitchExpression(SwitchExpressionTree node, Void ignored) {
            emit("branch", node, "", attrs(
                "branch_kind", "switch-expression",
                "condition_tokens", identifiers(node.getExpression()),
                "test_span", span(node.getExpression()),
                "body_span", span(node),
                "alternate_span", Collections.emptyMap(),
                "terminal", "none",
                "negative_test", false));
            return super.visitSwitchExpression(node, ignored);
        }

        @Override
        public Void visitConditionalExpression(ConditionalExpressionTree node, Void ignored) {
            emit("branch", node, "", attrs(
                "branch_kind", "conditional-expression",
                "condition_tokens", identifiers(node.getCondition()),
                "test_span", span(node.getCondition()),
                "body_span", span(node.getTrueExpression()),
                "alternate_span", span(node.getFalseExpression()),
                "terminal", "none",
                "negative_test", negative(node.getCondition())));
            return super.visitConditionalExpression(node, ignored);
        }
    }

    public static void main(String[] args) {
        int maxNodes = args.length > 0 ? Integer.parseInt(args[0]) : 100000;
        int maxDepth = args.length > 1 ? Integer.parseInt(args[1]) : 128;
        try {
            String source = readInput();
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) {
                row("M", "java-parser-unavailable", "system-compiler-missing", "0");
                return;
            }
            DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
            JavacTask task = (JavacTask) compiler.getTask(null, null, diagnostics,
                Arrays.asList("-proc:none", "-Xlint:none"), null,
                Collections.singletonList(new SourceUnit(source)));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
                    row("M", "parse-failed", "javac-diagnostic-error", "0");
                    return;
                }
            }
            Trees trees = Trees.instance(task);
            int count = 0;
            for (CompilationUnitTree unit : units) {
                Scanner scanner = new Scanner(unit, trees.getSourcePositions(), maxNodes, maxDepth);
                scanner.scan(unit, null);
                count += scanner.nodeCount();
            }
            row("M", "parsed", "", Integer.toString(count));
        } catch (LimitExceeded error) {
            row("M", error.status, error.status, "0");
        } catch (Exception error) {
            row("M", "parse-failed", error.getClass().getSimpleName(), "0");
        }
    }
}
