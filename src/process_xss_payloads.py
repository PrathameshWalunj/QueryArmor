import os
from tqdm import tqdm
from xss_payload_modifier import smart_tamper, generate_payloads

def load_original_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def save_payloads(payloads, file_path):
    with open(file_path, 'w') as file:
        for payload in payloads:
            file.write(f"{payload}\n")

def main():
    # Get the correct path to original_xss_payloads.txt
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)  # Go up one level from 'src'
    original_file = os.path.join(project_root, "original_xss_payloads.txt")

    # Load original payloads
    original_payloads = load_original_payloads(original_file)

    # Transform original payloads
    transformed_payloads = [smart_tamper(payload) for payload in tqdm(original_payloads, desc="Transforming Payloads")]

    # Generate additional payloads
    additional_payloads = generate_payloads(2000)

    # Combine all payloads
    all_payloads = original_payloads + transformed_payloads + additional_payloads

    # Remove duplicates 
    all_payloads = list(dict.fromkeys(all_payloads))

    # Save all payloads
    output_file = os.path.join(project_root, "transformed_xss_payloads.txt")
    save_payloads(all_payloads, output_file)

    print(f"Total payloads generated: {len(all_payloads)}")
    print(f"Original payloads: {len(original_payloads)}")
    print(f"Transformed original payloads: {len(transformed_payloads)}")
    print(f"Additional generated payloads: {len(additional_payloads)}")

if __name__ == "__main__":
    main()