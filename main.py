import ast

def code_walk(code_variable):
    tree = ast.parse(code_variable)

    # Find vulnerable lines
    vul_lines = find_user_input(tree)

    return vul_lines




def find_user_input(tree):
    t_status = {}
    vul_lines = []

    def check_t(node):
        if isinstance(node, ast.Name):
            if t_status.get(node.id):
                return True
        elif isinstance(node, ast.BinOp):
            if check_t(node.left) or check_t(node.right):
                return True
        else:
            for child in ast.iter_child_nodes(node):
                if check_t(child):
                    return True
        return False

    def traverse(node):
        # Input calls
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'input':
                # Node itself is the parent node, should have assign targets:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        t_status[target.id] = True
            else:
                # If depends on other tainted variables, add to t_status
                if isinstance(node.value, ast.Name):
                    if t_status.get(node.value.id):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                t_status[target.id] = True
                # Catch binary operations
                elif isinstance(node.value, ast.BinOp):
                    # Handle nested binary ops.
                    # Recursively check if there are any tainted variables.
                    flag = False
                    flag = flag or check_t(node.value.left) or check_t(node.value.right)

                    if flag:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                t_status[target.id] = True
                # Catch function calls
                elif isinstance(node.value, ast.Call):
                    flag = False
                    for arg in node.value.args:
                        if t_status.get(arg.id):
                            flag = True
                            break
                    if flag:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                t_status[target.id] = True
                else:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            t_status[target.id] = False

        # ID sink functions like exec()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'exec':
                # Check if it uses tainted arguments
                for arg in node.args:
                    if t_status.get(arg.id):
                        # Report the vulnerable line
                        print(f"Vulnerable line: {node.lineno}")
                        vul_lines.append(node.lineno)


        for child in ast.iter_child_nodes(node):
            traverse(child)

    traverse(tree)
    return vul_lines

# Get python code from a file.

with open('example_code.py', 'r') as file:
    code = file.read()

res = code_walk(code)

print(res)
