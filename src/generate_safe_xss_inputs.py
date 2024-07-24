import random
import os

html_content = ['Welcome to our website', 'About Us', 'Contact Information', 'Product Catalog', 'Latest News', 'FAQ']
css_classes = ['header', 'main-content', 'footer', 'nav-menu', 'btn-primary', 'form-control', 'card', 'alert-info']
js_variables = ['userData', 'productList', 'pageCount', 'currentIndex', 'totalItems', 'isLoggedIn', 'cartItems']
js_functions = ['updateUI', 'fetchData', 'validateForm', 'showModal', 'hideElement', 'scrollToTop']
url_params = ['id', 'page', 'category', 'search', 'sort', 'filter']
common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it', 'for', 'on', 'with', 'as', 'you', 'do', 'at']

def generate_safe_html():
    tags = ['div', 'p', 'span', 'a', 'h1', 'h2', 'h3']
    return f"<{random.choice(tags)} class=\"{random.choice(css_classes)}\">{random.choice(html_content)}</{random.choice(tags)}>"

def generate_safe_js():
    return f"function {random.choice(js_functions)}() {{ let {random.choice(js_variables)} = document.getElementById('{random.choice(css_classes)}').value; }}"

def generate_safe_url_param():
    return f"?{random.choice(url_params)}={random.choice(common_words)}+{random.choice(common_words)}"

def generate_safe_form_input():
    input_types = ['text', 'email', 'number', 'date']
    labels = ['Username', 'Email', 'Age', 'Date of Birth']
    i = random.randint(0, len(input_types) - 1)
    return f"<label for=\"{labels[i].lower()}\">{labels[i]}:</label><input type=\"{input_types[i]}\" id=\"{labels[i].lower()}\" name=\"{labels[i].lower()}\" value=\"{random.choice(common_words)}\">"

def generate_safe_input():
    generators = [generate_safe_html, generate_safe_js, generate_safe_url_param, generate_safe_form_input]
    return random.choice(generators)()

def load_existing_safe_inputs(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)

    existing_safe_file = os.path.join(project_root, "safe_user_inputs.txt")
    existing_safe_inputs = load_existing_safe_inputs(existing_safe_file)

    num_additional_safe = 5000  # Adjust as needed
    new_safe_inputs = [generate_safe_input() for _ in range(num_additional_safe)]

    all_safe_inputs = existing_safe_inputs + new_safe_inputs
    random.shuffle(all_safe_inputs)

    output_file = os.path.join(project_root, "safe_user_inputs_xss.txt")
    with open(output_file, 'w') as f:
        for input in all_safe_inputs:
            f.write(f"{input}\n")

    print(f"Total safe inputs: {len(all_safe_inputs)}")
    print(f"Existing safe inputs: {len(existing_safe_inputs)}")
    print(f"New XSS-specific safe inputs: {len(new_safe_inputs)}")
    print(f"Safe inputs saved to: {output_file}")

if __name__ == "__main__":
    main()